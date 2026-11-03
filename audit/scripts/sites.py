#!/usr/bin/env python3
# Consolidate vhosts -> site list (one row per vhost conf / docroot).
import os, re, json, glob

OUT = '/root/spamchecker-audit-20261103'
vhosts = json.load(open(OUT + '/vhosts.json'))
docs = json.load(open(OUT + '/docroots.json'))
doc_by_root = {d['docroot']: d for d in docs}

# docroots that are parents of referenced roots (e.g. /x/public) are "referenced indirectly"
sub_prefixes = [v['root_path'] for v in vhosts if v.get('root_path')]

def is_referenced(docroot):
    for r in sub_prefixes:
        if r == docroot or r.startswith(docroot + '/'):
            return True
    return False

def primary_domain(names):
    names = [n for n in names if not n.startswith('*')]
    bare = [n for n in names if not n.startswith('www.')]
    if bare:
        # shortest = the apex usually
        return sorted(bare, key=lambda s: (len(s), s))[0]
    wild = [n for n in vhosts]  # noop
    return names[0] if names else ''

sites = []
for v in vhosts:
    rp = v.get('root_path')
    if not rp: continue
    webroot = rp
    is_sub = bool(v.get('root_expr') and '$subdomain' in v['root_expr'])
    eff = v.get('effective_docroot') or rp
    d = doc_by_root.get(rp) or doc_by_root.get(eff) or {}
    sites.append({
        'conf': v['conf'],
        'user': v['user'],
        'domain': primary_domain(v['domains']),
        'names': v['domains'],
        'docroot': rp,
        'webroot': rp,
        'docroot_parent': os.path.dirname(os.path.dirname(os.path.dirname(rp))),
        'subdomain_pattern': is_sub,
        'socket': v.get('socket') or '',
        'auth_basic': v.get('auth_basic') or '',
        'wp': d.get('wp', []),
        'php': d.get('php', ''),
        'pool': d.get('pool', ''),
        'exists': d.get('exists', os.path.isdir(rp)),
        'top_entries': d.get('top_entries', 0),
        'subdomain_dirs': d.get('subdomain_dirs', []),
        'cms_guess': d.get('cms_guess', []),
    })

# sort: non-WP first
sites.sort(key=lambda s: (bool(s['wp']), s['domain']))
json.dump(sites, open(OUT + '/sites.json', 'w'), ensure_ascii=False, indent=1)
with open(OUT + '/sites.tsv', 'w') as fh:
    fh.write('domain\tdocroot\tsubdomain_pattern\tphp\tauth\twp\tentries\tconf\tnames\n')
    for s in sites:
        fh.write('\t'.join([s['domain'], s['docroot'], str(s['subdomain_pattern']), s['php'],
                            s['auth_basic'], 'WP' if s['wp'] else '', str(s['top_entries']),
                            s['conf'], ' '.join(s['names'])]) + '\n')
nwp = [s for s in sites if not s['wp']]
print('sites:', len(sites), '| non-WP:', len(nwp), '| WP:', len(sites) - len(nwp))
print('non-WP with php socket:', sum(1 for s in nwp if s['socket']))
print('non-WP no socket (static/other):', sum(1 for s in nwp if not s['socket']))
print('non-WP auth_basic:', sum(1 for s in nwp if s['auth_basic']))
print('subdomain-pattern sites:', sum(1 for s in nwp if s['subdomain_pattern']))
print()
print('--- non-WP site domains ---')
for s in nwp:
    print('%-40s %-62s php=%-3s %s%s' % (s['domain'], s['docroot'], s['php'],
          'AUTH ' if s['auth_basic'] else '', 'SUB' if s['subdomain_pattern'] else ''))
