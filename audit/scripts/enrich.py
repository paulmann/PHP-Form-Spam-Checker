#!/usr/bin/env python3
# Enrich sites with PHP socket/version and basic-auth info from vhost + vhosts-resources + users-resources.
import os, re, json, glob

OUT = '/root/spamchecker-audit-20261103'
sites = json.load(open(OUT + '/sites.json'))
vhosts = json.load(open(OUT + '/vhosts.json'))

POOL_DIRS = glob.glob('/opt/php*/etc/php-fpm.d/pool.d') + glob.glob('/etc/php/*/fpm/pool.d')
def php_ver(p):
    m = re.search(r'/opt/php(\d)(\d)', p)
    if m: return m.group(1) + '.' + m.group(2)
    m = re.search(r'/etc/php/(\d+\.\d+)/', p)
    return m.group(1) if m else '?'
pools = {}
for d in POOL_DIRS:
    for f in glob.glob(d + '/*.conf'):
        try: txt = open(f, encoding='utf-8', errors='replace').read()
        except Exception: continue
        name = None
        for line in txt.splitlines():
            m = re.match(r'\s*\[([^\]]+)\]', line)
            if m: name = m.group(1)
            m = re.match(r'\s*listen\s*=\s*(\S+)', line)
            if m: pools[m.group(1)] = {'file': f, 'pool': name, 'php': php_ver(d)}
SOCK2POOL = pools

def files_for(site):
    fs = [site['conf']]
    names = set(site['names'])
    for n in names:
        fs += glob.glob('/etc/nginx/vhosts-resources/%s/*.conf' % n)
        fs += glob.glob('/etc/nginx/vhosts-resources/%s/dynamic/*.conf' % n)
    fs += glob.glob('/etc/nginx/users-resources/%s/*.conf' % site['user'])
    fs += glob.glob('/etc/nginx/users-resources/%s/dynamic/*.conf' % site['user'])
    out = []
    seen = set()
    for f in fs:
        if f in seen or not os.path.isfile(f): continue
        seen.add(f); out.append(f)
    return out

def text(f):
    try: return open(f, encoding='utf-8', errors='replace').read()
    except Exception: return ''

for s in sites:
    sockets, auths, roots, proxies = [], [], [], []
    first_seen = {}
    for f in files_for(s):
        t = text(f)
        for m in re.finditer(r'fastcgi_pass\s+unix:([^;\s]+)', t):
            sockets.append((m.group(1), f))
        for m in re.finditer(r'auth_basic\s+("([^"]*)"|([^;\s]+))\s*;', t):
            v = m.group(2) or m.group(3) or ''
            if v and v != 'off': auths.append((v, f))
        for m in re.finditer(r'^\s*root\s+([^;]+);', t, re.M):
            roots.append((m.group(1).strip(), f))
        for m in re.finditer(r'proxy_pass\s+([^;]+);', t):
            proxies.append((m.group(1).strip(), f))
    # pick socket: prefer the one from the vhost conf if present, else resources
    sock = None
    if s['socket']:
        sock = s['socket']
    elif sockets:
        sock = sockets[0][0]
    s['socket_eff'] = sock or ''
    s['pool_eff'] = (SOCK2POOL.get(sock) or {}).get('pool', '') if sock else ''
    s['php_eff'] = (SOCK2POOL.get(sock) or {}).get('php', '') if sock else s.get('php', '')
    s['pool_file'] = (SOCK2POOL.get(sock) or {}).get('file', '') if sock else ''
    s['auth_rules'] = [{'value': a[0], 'file': a[1]} for a in auths]
    s['root_overrides'] = [{'value': a[0], 'file': a[1]} for a in roots]
    s['proxies'] = [{'value': a[0], 'file': a[1]} for a in proxies]
    s['config_files'] = files_for(s)

json.dump(sites, open(OUT + '/sites2.json', 'w'), ensure_ascii=False, indent=1)
nosock = [s for s in sites if not s['wp'] and not s['socket_eff']]
print('sites:', len(sites), '| non-WP without php socket:', len(nosock))
for s in nosock:
    print('  NOPHP', s['domain'], s['docroot'])
print('--- auth rules (non-WP):')
for s in sites:
    if s['wp']: continue
    for a in s['auth_rules']:
        print('  %-32s %-40s %s' % (s['domain'], a['value'][:40], a['file']))
print('--- proxies (non-WP):')
for s in sites:
    if s['wp']: continue
    for p in s['proxies']:
        print('  %-32s %-60s %s' % (s['domain'], p['value'][:60], p['file']))
