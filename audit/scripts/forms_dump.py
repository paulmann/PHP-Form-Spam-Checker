#!/usr/bin/env python3
import json, re, urllib.parse, os
OUT = '/root/spamchecker-audit-20261103'
probe = json.load(open(OUT + '/probe.json'))
sites = json.load(open(OUT + '/sites.json'))
by_dom = {}
for s in sites:
    by_dom.setdefault(s['domain'], s)

def p(u):
    try:
        x = urllib.parse.urlparse(u)
        return (x.path or '/') + (('?' + x.query) if x.query else '')
    except Exception:
        return u

print('%-34s %-4s %-14s %-5s %-34s %s' % ('domain', 'code', 'method', 'n', 'action', 'fields'))
for r in sorted(probe, key=lambda x: x['domain']):
    if r.get('wp'): continue
    for f in r.get('forms', []):
        fields = ','.join(sorted(set(x['name'] for x in f['fields'] if x['name'])))
        print('%-34s %-4s %-14s %-5s %-34s %s' % (r['domain'], r.get('status'), f['method'],
              len(f['fields']), p(f['action_abs'])[:34], fields[:110]))
