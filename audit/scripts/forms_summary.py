#!/usr/bin/env python3
import json, re, urllib.parse, os
OUT = '/root/spamchecker-audit-20261103'
probe = json.load(open(OUT + '/probe.json'))
sites = json.load(open(OUT + '/sites.json'))
by_dom = {}
for s in sites: by_dom.setdefault(s['domain'], s)
NOISE = re.compile(r'^/(lang|theme)/')

def path(u):
    try:
        x = urllib.parse.urlparse(u); return (x.path or '/') + (('?' + x.query) if x.query else '')
    except Exception: return u

for r in sorted(probe, key=lambda x: x['domain']):
    if r.get('wp'): continue
    keyed = {}
    for f in r.get('forms', []):
        a = f['action_abs']; k = (a, f['method'])
        keyed.setdefault(k, {'n': 0, 'pages': set(), 'fields': set(), 'enctype': f.get('enctype', '')})
        keyed[k]['n'] += 1
        keyed[k]['pages'].add(path(f['page']))
        keyed[k]['fields'] |= set(x['name'] for x in f['fields'] if x['name'])
    if not keyed and not r.get('third_party') and not r.get('iframes'): continue
    print('### %s  [%s] %s  docroot=%s php=%s' % (r['domain'], r.get('status'), ('AUTH' if r.get('auth_basic') else ''),
          r.get('docroot'), r.get('php')))
    if r.get('title'): print('    title:', r['title'][:100])
    if r.get('generator'): print('    generator:', r['generator'])
    if r.get('third_party'): print('    3rd-party markers:', ','.join(r['third_party']))
    for im in r.get('iframes', [])[:4]:
        print('    iframe:', im['abs'][:120])
    for (a, m), v in sorted(keyed.items(), key=lambda kv: -kv[1]['n']):
        if NOISE.search(urllib.parse.urlparse(a).path or ''): continue
        ext = urllib.parse.urlparse(a).netloc
        tag = ('EXT:' + ext) if ext and ext not in (r['domain'], 'www.' + r['domain']) else path(a)
        print('    %-4s %-45s x%-3d fields=%s pages=%s' % (m, tag[:45], v['n'], ','.join(sorted(v['fields']))[:80],
              ','.join(sorted(v['pages']))[:60]))
    print()
