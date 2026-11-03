#!/usr/bin/env python3
# Read-only docroot scan: <form> tags, $_POST reads, mail()/PHPMailer, DB inserts, lib includes.
import os, re, json, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

OUT = '/root/spamchecker-audit-20261103'
EXC = ['node_modules', 'vendor', '.git', '.svn', 'wp-content', 'wp-includes', 'wp-admin',
       'cache', 'tmp', 'uploads', 'backup', 'backups', 'logs', '.cache', 'bower_components']
PRUNE_ARGS = []
for e in EXC:
    PRUNE_ARGS += ['--exclude-dir=' + e]
TEXT_EXT = r'--include=*.php --include=*.html --include=*.htm --include=*.phtml --include=*.tpl --include=*.twig --include=*.inc --include=*.shtml'

def grep_files(root, pattern, extra_include=True):
    cmd = ['grep', '-rIl', '--binary-files=without-match', '--max-count=3'] + PRUNE_ARGS + \
          (TEXT_EXT.split() if extra_include else []) + ['-E', pattern, root]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=180)
        return [x for x in p.stdout.decode('utf-8', 'replace').split('\n') if x]
    except subprocess.TimeoutExpired:
        return []

def scan_file(path, root):
    rec = {'file': path, 'rel': os.path.relpath(path, root), 'forms': [], 'post_reads': [],
           'mail': [], 'db': [], 'libs': [], 'size': 0}
    try:
        rec['size'] = os.path.getsize(path)
        if rec['size'] > 4_000_000: return rec
        txt = open(path, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        return rec
    lines = txt.split('\n')
    for i, ln in enumerate(lines, 1):
        if len(ln) > 4000: ln = ln[:4000]
        low = ln.lower()
        if '<form' in low:
            rec['forms'].append({'line': i, 'text': re.sub(r'\s+', ' ', ln.strip())[:300]})
        if '$_post' in low or '$_request' in low:
            if re.search(r'(\$_POST|\$_REQUEST)\s*\[', ln):
                rec['post_reads'].append({'line': i, 'text': re.sub(r'\s+', ' ', ln.strip())[:200]})
        if re.search(r'\bmail\s*\(', ln) or 'phpmailer' in low or 'mailer->send' in low or '->send()' in low:
            rec['mail'].append({'line': i, 'text': re.sub(r'\s+', ' ', ln.strip())[:200]})
        if re.search(r'(insert\s+into|update\s+\w+\s+set|->query\s*\()', low):
            rec['db'].append({'line': i, 'text': re.sub(r'\s+', ' ', ln.strip())[:200]})
        if re.search(r'(require|include)(_once)?\s*\(?\s*["\']?[^"\']*lib/', ln) or '/var/www/lib' in ln or 'spl_autoload' in low or 'autoload.php' in low:
            rec['libs'].append({'line': i, 'text': re.sub(r'\s+', ' ', ln.strip())[:200]})
    return rec

def scan_site(s):
    root = s['webroot']
    res = {'domain': s['domain'], 'docroot': s['docroot'], 'webroot': root, 'php': s.get('php', ''),
           'files_with_form': [], 'form_files': [], 'post_files': [], 'mail_files': [],
           'lib_files': [], 'summary': {}}
    if not os.path.isdir(root):
        res['summary'] = {'error': 'webroot missing'}
        return res
    form_files = grep_files(root, r'<form[ >]')
    post_files = grep_files(root, r'\$_(POST|REQUEST)\s*\[')
    mail_files = grep_files(root, r'\bmail\s*\(|PHPMailer|mailer->send')
    lib_files = grep_files(root, r'/var/www/lib|spl_autoload|autoload\.php|(require|include).*lib/')
    res['files_with_form'] = [os.path.relpath(f, root) for f in form_files]
    for f in form_files[:120]:
        r = scan_file(f, root)
        if r['forms']: res['form_files'].append(r)
    for f in post_files[:80]:
        r = scan_file(f, root)
        if r['post_reads']: res['post_files'].append(r)
    for f in mail_files[:80]:
        r = scan_file(f, root)
        if r['mail']: res['mail_files'].append(r)
    for f in lib_files[:60]:
        r = scan_file(f, root)
        if r['libs']: res['lib_files'].append(r)
    res['summary'] = {'n_form_files': len(form_files), 'n_post_files': len(post_files),
                      'n_mail_files': len(mail_files), 'n_lib_files': len(lib_files)}
    return res

def main():
    sites = json.load(open(OUT + '/sites.json'))
    cand = [s for s in sites if not s['wp'] and s['exists']]
    if len(sys.argv) > 1:
        cand = [s for s in cand if re.search(sys.argv[1], s['domain'])]
    seen = set(); uniq = []
    for s in cand:
        key = s['webroot']
        if key in seen: continue
        seen.add(key); uniq.append(s)
    results = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(scan_site, uniq):
            results.append(r)
            sm = r['summary']
            print('%-38s formfiles=%-4s postfiles=%-4s mailfiles=%-3s libfiles=%s' % (
                r['domain'], sm.get('n_form_files'), sm.get('n_post_files'),
                sm.get('n_mail_files'), sm.get('n_lib_files')), flush=True)
    json.dump(results, open(OUT + '/scan.json', 'w'), ensure_ascii=False, indent=1)
    print('scanned', len(results), 'sites')

main()
