#!/usr/bin/env python3
# Enrich sites with PHP socket/version, basic-auth and effective webroot (handles $subdomain pattern).
import os, re, json, glob

OUT = '/root/spamchecker-audit-20261103'
sites = json.load(open(OUT + '/sites.json'))
vhosts = {v['conf']: v for v in json.load(open(OUT + '/vhosts.json'))}

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

def files_for(site):
    fs = [site['conf']]
    for n in sorted(set(site['names'])):
        if '*' in n:  # literal wildcard dir does not exist; still try apex
            continue
        for pat in ('/etc/nginx/vhosts-resources/%s/*.conf' % n,
                    '/etc/nginx/vhosts-resources/%s/dynamic/*.conf' % n):
            fs += [p for p in glob.glob(pat)]
    fs += glob.glob('/etc/nginx/users-resources/%s/*.conf' % site['user'])
    fs += glob.glob('/etc/nginx/users-resources/%s/dynamic/*.conf' % site['user'])
    out, seen = [], set()
    for f in fs:
        if f in seen or not os.path.isfile(f): continue
        seen.add(f); out.append(f)
    return out

def text(f):
    try: return open(f, encoding='utf-8', errors='replace').read()
    except Exception: return ''

def eff_webroot(site, vh):
    rp = site['docroot']
    if not site.get('subdomain_pattern'):
        return rp
    t = text(site['conf'])
    m = re.search(r'set\s+\$subdomain\s+("([^"]*)"|([^;\s]+))\s*;', t)
    default = ''
    if m:
        default = m.group(2) if m.group(2) is not None else m.group(3)
    if default:
        cand = os.path.join(rp, default)
        if os.path.isdir(cand):
            return cand
        return rp
    return rp

for s in sites:
    sockets, auths, roots, proxies = [], [], [], []
    for f in files_for(s):
        t = text(f)
        for m in re.finditer(r'fastcgi_pass\s+unix:([^;\s]+)', t):
            sockets.append((m.group(1), f))
        for m in re.finditer(r'auth_basic\s+("[^"]*"|[^;\s]+)\s*;', t):
            v = m.group(1).strip('"')
            if v and v != 'off': auths.append((v, f))
        for m in re.finditer(r'^\s*root\s+([^;]+);', t, re.M):
            roots.append((m.group(1).strip(), f))
        for m in re.finditer(r'proxy_pass\s+([^;]+);', t):
            proxies.append((m.group(1).strip(), f))
    sock = s['socket'] or (sockets[0][0] if sockets else None)
    s['socket_eff'] = sock or ''
    pi = pools.get(sock or '', {})
    s['pool_eff'] = pi.get('pool', '')
    s['php_eff'] = pi.get('php', s.get('php', ''))
    s['pool_file'] = pi.get('file', '')
    s['auth_rules'] = [{'value': a[0], 'file': a[1]} for a in auths]
    s['root_overrides'] = [{'value': a[0], 'file': a[1]} for a in roots]
    s['proxies'] = [{'value': a[0], 'file': a[1]} for a in proxies]
    s['config_files'] = files_for(s)
    s['webroot_eff'] = eff_webroot(s, vhosts.get(s['conf']))

json.dump(sites, open(OUT + '/sites2.json', 'w'), ensure_ascii=False, indent=1)
print('sites:', len(sites))
print('--- subdomain-pattern effective webroots:')
for s in sites:
    if s.get('subdomain_pattern'):
        print('  %-28s %s -> %s' % (s['domain'], s['docroot'], s['webroot_eff']))
print('--- non-WP with php: %d, without: %d' % (
    sum(1 for s in sites if not s['wp'] and s['socket_eff']),
    sum(1 for s in sites if not s['wp'] and not s['socket_eff'])))
print('--- non-WP public (no auth rules):', sum(1 for s in sites if not s['wp'] and not s['auth_rules']))
print('--- sites with support-form proxy:')
for s in sites:
    for p in s['proxies']:
        if '/support' in p['value'] or 'z.batteryservice' in p['value']:
            print('  %-30s %-45s %s' % (s['domain'], p['value'], p['file']))
