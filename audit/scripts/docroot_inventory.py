#!/usr/bin/env python3
# Read-only: pools + docroot inventory.
import os, re, glob, json, subprocess, sys

OUT = '/root/spamchecker-audit-20261103'
POOL_DIRS = sorted(glob.glob('/opt/php*/etc/php-fpm.d/pool.d') +
                   glob.glob('/etc/php/*/fpm/pool.d') +
                   glob.glob('/var/www/php-fpm') )

def php_ver_from_path(p):
    m = re.search(r'/opt/php(\d)(\d)', p)
    if m: return m.group(1) + '.' + m.group(2)
    m = re.search(r'/etc/php/(\d+\.\d+)/', p)
    if m: return m.group(1)
    return '?'

def scan_pools():
    pools = {}
    for d in POOL_DIRS:
        if not os.path.isdir(d): continue
        for f in sorted(glob.glob(d + '/*.conf')):
            name, listen, user, logv, pv = None, None, None, None, php_ver_from_path(d)
            try: txt = open(f, encoding='utf-8', errors='replace').read()
            except Exception: continue
            for line in txt.splitlines():
                st = line.strip()
                m = re.match(r'\[([^\]]+)\]', st)
                if m: name = m.group(1)
                m = re.match(r'listen\s*=\s*(\S+)', st)
                if m: listen = m.group(1)
                m = re.match(r'user\s*=\s*(\S+)', st)
                if m: user = m.group(1)
                m = re.match(r'php_admin_value\[error_log\]\s*=\s*(\S+)', st)
                if m: logv = m.group(1)
            if listen:
                pools[listen] = {'pool_file': f, 'pool': name, 'php': pv, 'fpm_user': user, 'error_log': logv}
    return pools

def wp_check(root):
    hits = []
    for rel in ('wp-config.php', 'wp-load.php', 'wp-settings.php', 'wp-content', 'wp-includes', 'wp-login.php'):
        if os.path.exists(os.path.join(root, rel)): hits.append(rel)
    return hits

def cms_guess(root, entries, dirs):
    g = []
    if 'bitrix' in dirs: g.append('bitrix')
    if 'configuration.php' in entries or 'configuration.php-dist' in entries: g.append('joomla')
    if 'tilda' in dirs or any(e.startswith('tilda') for e in entries): g.append('tilda')
    if 'modx' in dirs or 'manager' in dirs and 'config.core.php' in entries: g.append('modx')
    if 'app' in dirs and 'vendor' in dirs: g.append('symfony/laravel-ish')
    if 'node_modules' in dirs: g.append('node')
    if 'public' in dirs: g.append('public/ webroot')
    return g

def main():
    vhosts = json.load(open(OUT + '/vhosts.json'))
    # domain -> vhost (primary names first)
    dom2vhost = {}
    for v in vhosts:
        for d in v['domains']:
            dom2vhost.setdefault(d, v)
    # docroots referenced by vhosts (strip <subdomain>)
    referenced = {}
    for v in vhosts:
        rp = v.get('root_path')
        if not rp: continue
        if v.get('root_expr') and '$subdomain' in v['root_expr']:
            referenced[rp] = v  # root itself; subdirs handled separately
        else:
            referenced[rp] = v
    # actual docroots on disk
    disk = sorted(glob.glob('/var/www/*/data/www/*'))
    disk = [d for d in disk if os.path.isdir(d)]
    allroots = sorted(set(list(disk) + list(referenced.keys())))

    pools = scan_pools()
    rows = []
    for root in allroots:
        exists = os.path.isdir(root)
        entries, dirs = [], []
        if exists:
            try:
                entries = sorted(os.listdir(root))
                dirs = [e for e in entries if os.path.isdir(os.path.join(root, e))]
            except PermissionError:
                entries = ['<PERMISSION DENIED>']
        v = referenced.get(root)
        socket = v['socket'] if v else None
        pool = pools.get(socket, {}) if socket else {}
        wp = wp_check(root) if exists else []
        subdirs = []
        if v and v.get('root_expr') and '$subdomain' in v['root_expr'] and exists:
            subdirs = [e for e in dirs if not e.startswith('.')][:200]
        rows.append({
            'docroot': root,
            'owner': root.split('/')[3] if root.startswith('/var/www/') else '',
            'exists': exists,
            'referenced_by_vhost': bool(v),
            'conf': v['conf'] if v else '',
            'domains': v['domains'] if v else [],
            'socket': socket or '',
            'pool': pool.get('pool', ''),
            'php': pool.get('php', ''),
            'pool_file': pool.get('pool_file', ''),
            'wp': wp,
            'auth_basic': (v.get('auth_basic') or '') if v else '',
            'top_entries': len(entries),
            'top_dirs': dirs[:40],
            'subdomain_dirs': subdirs,
            'cms_guess': cms_guess(root, entries, dirs) if exists else [],
        })
    json.dump(rows, open(OUT + '/docroots.json', 'w'), ensure_ascii=False, indent=1)
    # tsv summary
    with open(OUT + '/docroots.tsv', 'w') as fh:
        fh.write('docroot\towner\texists\tvhost\tdomains\tphp\twp\tcms\tentries\tauth\n')
        for r in rows:
            fh.write('\t'.join([r['docroot'], r['owner'], str(r['exists']), r['conf'],
                                ' '.join(r['domains']), r['php'],
                                ','.join(r['wp']), ','.join(r['cms_guess']),
                                str(r['top_entries']), r['auth_basic']]) + '\n')
    wpn = [r for r in rows if r['wp']]
    orphan = [r for r in rows if not r['referenced_by_vhost']]
    print('docroots total:', len(rows), '| on disk:', sum(1 for r in rows if r['exists']))
    print('wordpress:', len(wpn))
    print('orphan (on disk, no vhost):', len(orphan))
    for r in orphan: print('  ORPHAN', r['docroot'], 'entries=%d' % r['top_entries'])
    print('pools scanned:', len(pools))
    missing = [r['docroot'] for r in rows if r['referenced_by_vhost'] and not r['exists']]
    print('vhost docroot missing on disk:', len(missing))
    for m in missing: print('  MISSING', m)

main()
