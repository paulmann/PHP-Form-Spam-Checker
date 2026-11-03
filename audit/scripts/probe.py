#!/usr/bin/env python3
# Read-only HTTP probe + form extraction. GET only, never POST.
import json, subprocess, re, os, sys, time, urllib.parse, html as htmlmod
from concurrent.futures import ThreadPoolExecutor

OUT = '/root/spamchecker-audit-20261103'
EV = OUT + '/evidence'
IP = '176.99.5.35'
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128 Safari/537.36 AuditReadOnly/1.0'

PAGE_HINTS = re.compile(r'(kontakt|contact|contactus|feedback|obratn|form|order|zakaz|support|callback|call|reg|price|question|write|otzyv|review|dostavka|paid|oplat|svyaz|zayav|request|quote|calc)', re.I)

def sh(cmd, timeout=45):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return -1, '', 'timeout'

def fetch(host, url, outfile):
    fmt = '%{http_code}\t%{redirect_url}\t%{size_download}\t%{content_type}\t%{time_total}'
    cmd = ['curl', '-sk', '--max-time', '20', '--resolve', host + ':443:' + IP,
           '-A', UA, '-o', outfile, '-w', fmt, url]
    rc, so, se = sh(cmd)
    parts = (so.strip().split('\t') + [''] * 5)[:5]
    return {'code': parts[0] if rc >= 0 else 'ERR', 'redirect': parts[1], 'size': parts[2],
            'ctype': parts[3], 'time': parts[4], 'err': se.strip()[-200:] if rc < 0 else ''}

ATTR = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))')

def attrs(s):
    d = {}
    for m in ATTR.finditer(s):
        v = m.group(3) if m.group(3) is not None else (m.group(4) if m.group(4) is not None else m.group(5))
        d[m.group(1).lower()] = htmlmod.unescape(v or '')
    return d

FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
FIELD_RE = re.compile(r'<(input|textarea|select)\b([^>]*)>', re.I)
IFRAME_RE = re.compile(r'<iframe\b([^>]*)>', re.I)
SCRIPT_RE = re.compile(r'<script\b([^>]*)>', re.I)
TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
LINK_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.I)
THIRD = re.compile(r'(jotform|tilda|bitrix24|b24|google\.com/forms|forms\.gle|typeform|formspree|mailchimp|sendpulse|marquiz|callibri|envybox|roistat|verbox|amocrm|getform|formcarry|smartcaptcha|recaptcha)', re.I)

def extract(page_url, body):
    out = {'forms': [], 'iframes': [], 'third_party': [], 'generator': '', 'title': ''}
    m = TITLE_RE.search(body)
    if m: out['title'] = re.sub(r'\s+', ' ', htmlmod.unescape(re.sub(r'<[^>]+>', '', m.group(1)))).strip()[:150]
    m = GENERATOR_RE.search(body)
    if m: out['generator'] = m.group(1)[:80]
    for fm in FORM_RE.finditer(body):
        a = attrs(fm.group(1))
        inner = fm.group(2)
        fields = []
        for f in FIELD_RE.finditer(inner):
            fa = attrs(f.group(2))
            nm = fa.get('name') or fa.get('id') or ''
            fields.append({'tag': f.group(1).lower(), 'name': nm, 'type': fa.get('type', ''),
                           'required': 'required' in f.group(2).lower()})
        action = a.get('action', '')
        action_abs = urllib.parse.urljoin(page_url, action) if action else page_url
        snippet = re.sub(r'\s+', ' ', fm.group(0))[:600]
        out['forms'].append({'action': action, 'action_abs': action_abs, 'method': (a.get('method') or 'GET').upper(),
                             'name': a.get('name', ''), 'enctype': a.get('enctype', ''),
                             'fields': fields, 'snippet': snippet})
    for im in IFRAME_RE.finditer(body):
        a = attrs(im.group(1)); src = a.get('src', '')
        if src: out['iframes'].append({'src': src, 'abs': urllib.parse.urljoin(page_url, src)})
    for m in THIRD.finditer(body):
        out['third_party'].append(m.group(1).lower())
    out['third_party'] = sorted(set(out['third_party']))
    return out

def same_host(u, host):
    try:
        h = urllib.parse.urlparse(u).netloc.lower().split(':')[0]
    except Exception:
        return False
    if not h: return True
    base = host[4:] if host.startswith('www.') else host
    return h == host or h == 'www.' + base or h == base

def probe(site):
    host = site['domain']
    d = os.path.join(EV, 'html', re.sub(r'[^A-Za-z0-9._-]', '_', host))
    os.makedirs(d, exist_ok=True)
    res = {'domain': host, 'docroot': site['docroot'], 'php': site.get('php', ''),
           'auth_basic': site.get('auth_basic', ''), 'wp': bool(site.get('wp')),
           'subdomain_pattern': site.get('subdomain_pattern', False),
           'pages': [], 'forms': [], 'third_party': [], 'error': ''}
    hp = os.path.join(d, 'index.html')
    r = fetch(host, 'https://' + host + '/', hp)
    res['status'] = r['code']; res['redirect'] = r['redirect']; res['size'] = r['size']
    res['ctype'] = r['ctype']; res['time'] = r['time']; res['error'] = r['err']
    if r['code'] == '000' or r['code'] == 'ERR':
        res['error'] = res['error'] or 'connect failed'
        return res
    # if redirect to same host, fetch target once
    urls = ['https://' + host + '/']
    body = ''
    if os.path.exists(hp):
        body = open(hp, 'rb').read(3_000_000).decode('utf-8', 'replace')
    if r['redirect'] and same_host(r['redirect'], host) and r['redirect'].rstrip('/') != urls[0].rstrip('/'):
        tgt = r['redirect']
        fn = os.path.join(d, 'redirect_target.html')
        r2 = fetch(host, tgt, fn)
        res['pages'].append({'url': tgt, **{k: r2[k] for k in ('code', 'redirect', 'size', 'ctype')}})
        urls.append(tgt)
        if os.path.exists(fn): body = open(fn, 'rb').read(3_000_000).decode('utf-8', 'replace')
    if not res['wp'] and 'html' in (r['ctype'] or '') and body:
        ex = extract(urls[-1], body)
        res['title'] = ex['title']; res['generator'] = ex['generator']
        res['third_party'] += ex['third_party']; res['iframes'] = ex['iframes']
        for f in ex['forms']:
            f['page'] = urls[-1]; res['forms'].append(f)
        # follow internal candidate pages
        cand, seen = [], set(urls)
        for href in LINK_RE.findall(body):
            u = urllib.parse.urljoin(urls[-1], htmlmod.unescape(href))
            p = urllib.parse.urlparse(u)
            if not same_host(u, host): continue
            if p.scheme not in ('http', 'https'): continue
            clean = u.split('#')[0]
            path = p.path or '/'
            if clean in seen: continue
            if re.search(r'\.(jpg|jpeg|png|gif|svg|webp|pdf|zip|rar|css|js|xml|doc|docx|xls|xlsx|mp4|woff2?|ttf|ico)$', path, re.I): continue
            depth = len([x for x in path.split('/') if x])
            if depth > 3: continue
            score = 3 if PAGE_HINTS.search(path.lower()) else (1 if depth <= 1 else 0)
            if score == 0: continue
            seen.add(clean); cand.append((score, clean))
        cand.sort(key=lambda x: -x[0])
        for i, (sc, u) in enumerate(cand[:10]):
            fn = os.path.join(d, 'p%02d.html' % i)
            rr = fetch(host, u, fn)
            res['pages'].append({'url': u, 'code': rr['code'], 'redirect': rr['redirect'], 'size': rr['size']})
            if rr['code'] == '200' and os.path.exists(fn):
                b = open(fn, 'rb').read(3_000_000).decode('utf-8', 'replace')
                ex = extract(u, b)
                res['third_party'] += ex['third_party']
                res['iframes'] += ex['iframes']
                for f in ex['forms']:
                    f['page'] = u; res['forms'].append(f)
        res['third_party'] = sorted(set(res['third_party']))
    return res

def main():
    sites = json.load(open(OUT + '/sites.json'))
    # dedup by domain (some confs share domain name?)
    seen = set(); uniq = []
    for s in sites:
        if s['domain'] in seen: continue
        seen.add(s['domain']); uniq.append(s)
    only = sys.argv[1] if len(sys.argv) > 1 else None
    if only:
        uniq = [s for s in uniq if re.search(only, s['domain'])]
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(probe, uniq):
            results.append(r)
            fl = len(r.get('forms', []))
            print('%-38s %3s %-22s forms=%d %s' % (r['domain'], r.get('status'), (r.get('ctype') or '')[:22], fl,
                                                  ('REDIR ' + r['redirect'][:50]) if r.get('redirect') else ''), flush=True)
    json.dump(results, open(OUT + '/probe.json', 'w'), ensure_ascii=False, indent=1)
    print('done %d sites in %.1fs' % (len(results), time.time() - t0))

main()
