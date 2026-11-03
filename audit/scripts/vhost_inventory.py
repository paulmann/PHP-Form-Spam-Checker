#!/usr/bin/env python3
# Read-only nginx vhost inventory for 176.99.5.35. Writes nothing outside /root/spamchecker-audit-20261103.
import os, re, glob, json, sys

VH = '/etc/nginx/vhosts'
OUT = '/root/spamchecker-audit-20261103'

def split_blocks(text):
    blocks, cur, depth = [], None, 0
    for line in text.splitlines():
        if cur is None:
            if re.match(r'\s*server\s*\{', line):
                cur, depth = [], 0
            else:
                continue
        cur.append(line)
        # strip quoted strings to avoid brace counting issues
        s = re.sub(r'"[^"]*"', '""', line)
        s = re.sub(r"'[^']*'", "''", s)
        depth += s.count('{') - s.count('}')
        if depth <= 0:
            blocks.append('\n'.join(cur)); cur = None; depth = 0
    return blocks

def parse_block(b):
    d = {'server_name': [], 'listen443': False, 'root_path': None, 'root': None,
         'socket': None, 'auth_basic': None, 'redirect': False, 'error_log': None, 'includes': []}
    for line in b.splitlines():
        st = line.strip()
        m = re.match(r'server_name\s+([^;]+);', st)
        if m: d['server_name'] += m.group(1).split()
        if re.match(r'listen\s+[^;]*:443', st): d['listen443'] = True
        m = re.match(r'set\s+\$root_path\s+([^;]+);', st)
        if m: d['root_path'] = m.group(1)
        m = re.match(r'root\s+([^;]+);', st)
        if m: d['root'] = m.group(1)
        m = re.match(r'fastcgi_pass\s+unix:([^;]+);', st)
        if m: d['socket'] = m.group(1)
        m = re.match(r'auth_basic\s+(.+);', st)
        if m: d['auth_basic'] = m.group(1).strip().strip('"')
        if re.match(r'return\s+30\d', st): d['redirect'] = True
        m = re.match(r'error_log\s+([^ ]+)', st)
        if m: d['error_log'] = m.group(1)
        m = re.match(r'include\s+([^;]+);', st)
        if m: d['includes'].append(m.group(1))
    return d

def main():
    files = sorted(glob.glob(VH + '/*/*.conf'))
    files = [f for f in files if '.bak' not in os.path.basename(f)]
    rows = []
    for f in files:
        try:
            text = open(f, encoding='utf-8', errors='replace').read()
        except Exception as e:
            print('ERR', f, e, file=sys.stderr); continue
        blocks = [parse_block(b) for b in split_blocks(text)]
        if not blocks:
            continue
        user = f.split('/')[4]
        # prefer the ssl block for facts, else the first
        sslb = next((b for b in blocks if b['listen443']), None)
        b = sslb or blocks[0]
        names = sorted(set(b['server_name']) | set(n for x in blocks for n in x['server_name']))
        rootpath = b['root_path'] or next((x['root_path'] for x in blocks if x['root_path']), None)
        root = b['root'] or next((x['root'] for x in blocks if x['root']), None)
        socket = b['socket'] or next((x['socket'] for x in blocks if x['socket']), None)
        auth = b['auth_basic'] or next((x['auth_basic'] for x in blocks if x['auth_basic']), None)
        # effective docroot
        eff = None
        if rootpath:
            eff = rootpath
            if root and '$subdomain' in root:
                eff = rootpath + '/<subdomain>'
        # sanity: root without $root_path
        if root and rootpath and not root.startswith('$root_path') and '$subdomain' not in root:
            eff = root
        rows.append({
            'conf': f, 'user': user, 'domains': names, 'root_path': rootpath,
            'root_expr': root, 'effective_docroot': eff, 'socket': socket,
            'auth_basic': auth, 'ssl443': bool(b['listen443']),
            'https_blocks': sum(1 for x in blocks if x['listen443']),
        })
    with open(OUT + '/vhosts.json', 'w') as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=1)
    # TSV
    with open(OUT + '/vhosts.tsv', 'w') as fh:
        fh.write('conf\tuser\tdomains\tdocroot\tsocket\tauth_basic\thttps_blocks\n')
        for r in rows:
            fh.write('\t'.join([r['conf'], r['user'], ' '.join(r['domains']),
                                r['effective_docroot'] or '', r['socket'] or '',
                                r['auth_basic'] or '', str(r['https_blocks'])]) + '\n')
    # summary to stdout
    print('confs:', len(rows))
    print('with socket:', sum(1 for r in rows if r['socket']))
    print('auth_basic:', sum(1 for r in rows if r['auth_basic']))
    print('subdomain pattern:', sum(1 for r in rows if r['root_expr'] and '$subdomain' in r['root_expr']))
    doms = set(n for r in rows for n in r['domains'] if not n.startswith('*'))
    print('unique domains:', len(doms))

main()
