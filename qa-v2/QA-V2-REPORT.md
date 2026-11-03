# PHP-Form-Spam-Checker v2.0 — Independent QA report

- **Verifier:** qa (independent; no production changes, no library edits)
- **Report time:** 2026-11-03 ~21:35 Europe/Minsk (MSK)
- **Library:** `C:\AutoClaw\PHP-Form-Spam-Checker` / https://github.com/Paulmann/PHP-Form-Spam-Checker
- **Server:** `bs535` = 176.99.5.35, shared module `/var/www/lib/PHP-Form-Spam-Checker`
- **Local toolchain:** PHP 8.5.12 (`C:\tools\php8512\php.exe`), composer (`C:\tools\composer.phar`), git 2.56

> **Scope caveat (important):** the verification was cut short by the "final call". Everything below marked **PASS/FAIL** was actually executed and its output is quoted. Everything marked **NOT RUN / UNVERIFIED** was **not** executed — it is not a pass. In particular the whole live-attack matrix (v2 WAF 403, form-guard 400) and the library black-box suite were **not run**; code was read but not exercised.

## 1. Verdict summary

| # | Check | Result | Evidence |
|---|---|---|---|
| 1.1 | Fresh clone of branch `v2.0` | **PASS** | HEAD `c21bfb3` at clone time 20:46 |
| 1.2 | Branch head equals briefed HEAD `c21bfb3` | **FAIL (stale brief)** | remote `v2.0` is now `f7babd9` (2 commits ahead) |
| 1.3 | `composer.lock` tracked | **PASS** | `git ls-files composer.lock`; sha256 `4afec3ec…c4f4c14`, 251 953 B |
| 1.4 | No tags / no releases | **PASS** | `git ls-remote --tags` empty; GitHub releases API `0` |
| 1.5 | LICENSE = MIT | **PASS** | `MIT License / Copyright (c) 2026 Paulmann`; repo `licenseInfo.key=mit` |
| 1.6 | `composer validate --strict` | **PASS** | `./composer.json is valid`, exit 0 |
| 1.7 | `composer install` | **PASS** | exit 0 (dev deps incl. phpunit 12.x, phpstan, psalm, php-cs-fixer, PSR interfaces) |
| 1.8 | PHPUnit on PHP 8.5.12 = **496 tests / 1751 assertions** | **PASS** | `OK (496 tests, 1751 assertions)`, exit 0, 10.9 s |
| 1.9 | PHPStan level max + strict rules = 0 | **PASS** | `[OK] No errors`, exit 0 |
| 1.10 | Psalm taint analysis = 0 | **PASS** | `No errors found!`, 7.02 s, 98.14 % inferred, exit 0 |
| 1.11 | php-cs-fixer `--dry-run` = 0 files | **PASS** | `Found 0 of 169 files that can be fixed`, exit 0 |
| 1.12 | CI green on `v2.0` with 8.5.12+8.5 matrix and coverage-gate step | **PARTIAL** | green at current `f7babd9`; **red at the briefed `c21bfb3`** (coverage gate) — see 1.13 |
| 1.13 | CI at `c21bfb3` (the stated HEAD) | **FAIL** | run 41687281061 = `failure`; coverage gate exit 1: lines 76.81 % < 95 %, methods 65.31 % < 90 % |
| 1.23 | CI green on `main` at merged `f7babd9` | **PASS** | run 41692949307 = `success`, 2026-11-03T18:21:01Z |
| 1.14 | Deployed server == GitHub `v2.0` for 3 key files | **FAIL (1 of 3)** | `SpamChecker.php` and `Waf.php` match; `src/Data/RequestData.php` does **not** — see 3.2 |
| 1.15 | Deployed `config/sites` == local reference configs | **FAIL (6 of 7)** | only difference: `waf.mode` = `block` on server vs `monitor` in reference — see 3.3 |
| 1.16 | v2 deployed at all (waf-check, src/Waf, src/Data, CHANGELOG 2.0.0) | **PASS** | see 3.1 |
| 1.17 | WAF wired on PHP sites and in the Node bridge | **PASS (wiring only)** | `guard.php` runs WAF→FormGuard; Node `.env` `WAF_MODE=block`, `WAF_SCRIPT=…/bin/waf-check`; dist rebuilt + service restarted 20:59:31 |
| 1.18 | Live GET regression (7 URLs) | **PASS** | all `200`, see 4.1 |
| 1.19 | Live v2 spam/WAF probes (400+`X-Spam-Guard`, 403+`X-WAF`, 200 `{"ok":true}`) | **NOT RUN** | stopped by "final call"; **must not be reported as green** |
| 1.20 | Library black-box (pipeline, AbuseIPDB, DNSBL/SPF/DMARC, Bayes, behavioral, v1 compat) | **NOT RUN** | code read only |
| 1.21 | nginx error-log 2 h diff for the v2 deployment window | **NOT RUN** | v1-window check only (see 4.2) |
| 1.22 | No `bw@conbat.ru` mail during blocked tests | **N/A yet** | baseline only: 0 such mails in the 25 min before writing (no blocked tests were sent) |

## 2. Repository verification (executed)

Clone: `git clone --branch v2.0 --single-branch https://github.com/Paulmann/PHP-Form-Spam-Checker.git`
→ `HEAD = c21bfb31dfc5c30ca2dd6f5162c70e04edba62dd`, branch `v2.0`, 3 commits visible at clone time.

```
$ php C:\tools\composer.phar validate --strict
./composer.json is valid                                  (exit 0)

$ php vendor\bin\phpunit
PHPUnit 12.5.43 … Runtime: PHP 8.5.12
OK (496 tests, 1751 assertions)                           (exit 0)

$ php vendor\bin\phpstan analyse --no-progress --memory-limit=1G
[OK] No errors                                             (exit 0)

$ php vendor\bin\psalm --no-progress --taint-analysis
No errors found!                                           (exit 0)

$ php vendor\bin\php-cs-fixer fix --dry-run --diff
PHP CS Fixer 3.95.27 (PHP runtime: 8.5.12)
Found 0 of 169 files that can be fixed                     (exit 0)
```

Refs: `git ls-remote --tags` → empty. `gh api repos/…/releases --jq length` → `0`.
`composer.json`: `"license": "MIT"`, `"php": ">=8.5"`, dev-only dependencies, bins `spam-check`, `waf-check`, `spam-train`.
`composer.lock` **is** tracked in `v2.0` (contrary to a comment still present in `.github/workflows/ci.yml` at `c21bfb3`: "composer.lock is currently git-ignored").

## 3. CI — the claim is true only for the *new* head

`gh run list --branch v2.0`:

```
41692943607  success    docs: align coverage wording …        f7babd9  2026-11-03T18:20:59Z  (latest)
41692397933  cancelled  v2.0: in-process CLI/guard tests …    4b337b5  2026-11-03T18:17:37Z  (concurrency)
41692399712  success    CI (workflow_dispatch)                 4b337b5  2026-11-03T18:17:37Z
41687281061  failure    CI (workflow_dispatch)                 c21bfb3  2026-11-03T17:45:18Z  ← the briefed HEAD
41687246632  cancelled  v2.0.0: protection cycle complete …    c21bfb3  2026-11-03T17:45:06Z  (concurrency)
```

Failure log of step **"Coverage gate (95% lines / 90% methods …)"** in run 41687281061 (job `Quality gates (PHP 8.5.12)`):

```
files   : 70 analysed, excluded: FileCache, Psr16CacheAdapter, Psr6CacheAdapter,
          DnsGetRecordResolver, CurlClient, Psr18ClientAdapter, Psr3LoggerAdapter (7)
lines   : 3146/4096  76.81%  (threshold 95.00%)
methods : 322/493  65.31%  (threshold 90.00%)
result  : FAIL - line coverage 76.81% < 95.00%; method coverage 65.31% < 90.00%
##[error]Process completed with exit code 1.
```

Steps 1–12 of that job (cs-fixer, PHPStan, Psalm, strict tests, coverage report) were `success`; step 13 failed; step 14 (lint) `skipped`; the PHP 8.5 job was `success`. The earlier `c21bfb3` push run was `cancelled` by the workflow's `cancel-in-progress` concurrency, which is why only the dispatch run exposes the failure.

The branch then moved twice while I was verifying:

```
4b337b5  v2.0: in-process CLI/guard/endpoint tests (534 tests), 89.5% line coverage,
         coverage ratchet 88/72 in CI, request-data XFF priority fix
f7babd9  docs: align coverage wording with the measured gate (88/72, measured 89.5/73.4)
```

At `f7babd9` run 41692943607 is `success` with both matrix jobs
(`Quality gates (PHP 8.5.12)` success, `Quality gates (PHP 8.5)` success).

`main` at the same commit is green as well: run 41692949307 (2026-11-03T18:21:01Z) = `success`.

**Interpretation:** "CI green" is true for `f7babd9`/`4b337b5`, false for the HEAD named in the brief (`c21bfb3`). Note also that the gate was **relaxed** from 95/90 to 88/72 (measured 89.5/73.4) rather than coverage being raised to the documented 95 % — a documentation-vs-reality gap worth a decision, not a code bug.

## 4. Server deployment (executed, read-only)

### 4.1 Inventory (`ssh bs535`)

```
2026-11-03T21:26:37+03:00
bin/:      spam-check (15:47), waf-check (19:43, 390 B), spam-train (19:59, 365 B)
src/:      Bayes Behavioral Cache Check Cli Config Context Data Dns Exception FormProtector
           Http Integration Log Pipeline SpamChecker Status Storage Support Token Waf
src/Waf:   AbstractRule RuleInterface Rules Waf WafFinding WafRequest WafVerdict
CHANGELOG: ## [2.0.0] — 2026-11-03
module root 20:44, bin/ 20:52, config/sites/ 20:58, /var/www/bwo/dist 20:59,
bwo.service ExecMainStartTimestamp = 2026-11-03 20:59:31 MSK
```

`integrations/guard.php` now runs both layers:

```php
$waf = FormSpamChecker\Integration\WafGuard::boot();
if ($waf->enabled()) { $waf->run(); }
FormSpamChecker\Integration\FormGuard::boot()->run();
```

### 4.2 Hash comparison vs GitHub raw (`v2.0` = `f7babd9`)

| File | Server sha256 | GitHub raw sha256 | Verdict |
|---|---|---|---|
| `src/SpamChecker.php` | `dd9be9c5fb997c9e…5ba5bdd974` | `dd9be9c5fb997c9e…5ba5bdd974` | **MATCH** |
| `src/Waf/Waf.php` | `548504b86702004c…6027660812` | `548504b86702004c…6027660812` | **MATCH** |
| `src/Data/RequestData.php` | `8497cd059c39623f…74a8a104b` | `0221b806d2ec21d9…ddc4c55e2` | **MISMATCH** |

The deployed file equals the **`c21bfb3`** version, i.e. the server is **one commit behind** for this file and lacks the "request-data XFF priority fix":

```
line 240  GitHub v2.0 (f7babd9): if (!isset($server['HTTP_CF_CONNECTING_IP']) && isset($server['HTTP_X_FORWARDED_FOR']) && …)
line 240  deployed (c21bfb3)   : if (isset($server['HTTP_X_FORWARDED_FOR']) && …)
```

`src/SpamChecker.php` and `src/Waf/Waf.php` are exactly the GitHub `v2.0` content, so the deployment is *almost* current — but not identical to the branch that is now merged to `main`.

### 4.3 `config/sites` drift vs `C:\AutoClaw\spamchecker-integration\configs\`

Compared sha256 for every pair present on both sides (server files 20:58; local reference 20:20):

| Site config | Server | Local reference | Verdict |
|---|---|---|---|
| `bs12v.ru.php` | `63799bc1…6aea34a` | `63799bc1…6aea34a` | **MATCH** |
| `batterypassport.ru.php` | `ceb810c5…8afa6a` | `bb5bbc4e…267fc` | differ |
| `batterywizard.ru.php` | `6b0504ab…afebcd` | `c8015b06…ea1ccb` | differ |
| `bscharger.com.php` | `993de043…a26bf` | `9234dc84…03f882` | differ |
| `bscharger.ru.php` | `9a33ac6f…a7aaef` | `8e24ab62…f5b24a` | differ |
| `conbat.ru.php` | `3f5d8059…9b5bc8` | `8fc92b11…f81c63` | differ |
| `z.batteryservice.ru.php` | `86ec05ae…bf41a` | `8c3dab84…09c231` | differ |
| `default.php` | `8c97f2d9…e73297a` | (no counterpart) | n/a |

Line-by-line diff of two samples shows **exactly one differing line** in each, and the same in all six:

```
conbat.ru.php line 49         server: 'mode' => 'block',      local: 'mode' => 'monitor',
batterywizard.ru.php line 41  server: 'mode' => 'block',      local: 'mode' => 'monitor',
```

So: `waf.enabled = true` and **`waf.mode = block`** on the server for 6 of 7 sites, while the source-of-truth integration config set says `monitor`. `bs12v.ru` and `default.php` have no `waf` section. This contradicts the documented rollout ("start in `monitor`, review `var/log`, then switch") — may be intentional, but it is a real divergence between the reference configs and production.

### 4.4 WAF wiring

- PHP sites: `integrations/guard.php` → `WafGuard` first, then `FormGuard`; `waf.enabled=true` in the 6 site configs.
- Node/batterywizard: `bwo-src/src/lib/spam-guard.ts` has `checkWaf()` → `bin/waf-check`; `api/lead.ts` calls it and answers `403` when `waf.blocked`; `/var/www/bwo/.env` has `WAF_SCRIPT=/var/www/lib/PHP-Form-Spam-Checker/bin/waf-check` and `WAF_MODE=block`; rebuilt `dist` references `waf-check`; service restarted 20:59:31.
- This is **wiring proof only** — no attack request was sent (see 1.19).

## 5. Live checks actually performed

### 5.1 GET regression (browser UA, no attack payloads)

| URL | HTTP | bytes | guard headers |
|---|---|---|---|
| `https://batterywizard.ru/` | 200 | 54 934 | none |
| `https://batterywizard.ru/register/` | 200 | 21 815 | none |
| `https://batterywizard.ru/contacts/` | 200 | 22 146 | none |
| `https://batterywizard.ru/pricing/` | 200 | 40 978 | none |
| `https://conbat.ru/` | 200 | 134 302 | none |
| `https://bscharger.com/` | 200 | 90 751 | none |
| `https://batterypassport.ru/` | 200 | 61 713 | none |

`/contacts/` contains exactly one support iframe:
`<iframe class="zbs-support-embed" src="/support/form.php?token=<public site token>&embed_origin=https%3A%2F%2Fbatterywizard.ru" …>`.

Note: `batterypassport.ru` initially timed out because the **local Windows resolver** returned a stale `176.99.2.35`; `8.8.8.8`, `1.1.1.1` and the server's own resolver return `176.99.5.35`, and `curl --resolve batterypassport.ru:443:176.99.5.35` gives `200` in 50 ms. Test-side artifact, not a site fault.

### 5.2 Baseline for the mail check

`grep bw@conbat.ru /var/log/exim4/mainlog`: **0** entries in the last 25 minutes (last ones 01:51/01:59). No blocked-test traffic was produced, so there is nothing to compare — the "no mail for blocked tests" assertion is **not verified**.

### 5.3 Not executed (explicit)

- `POST conbat.ru/php/task-add.php` (curl UA) → expected `400` + `X-Spam-Guard: blocked`
- same endpoint, browser UA + incomplete body → expected application validation error, **no** guard header
- WAF attack request (SQLi/XSS) on `conbat.ru` and on batterywizard `/api/*` → expected `403` + `X-WAF: blocked` (mode=block) or pass + `[waf]` log in monitor
- `POST batterywizard.ru/api/lead` spam-keywords → expected `200 {"ok":true}` (silent block) + verdict log line
- `https://conbat.ru/support/form.php` no-token (`404 "Форма недоступна"`) and spam POST (`400` + `X-Spam-Guard`)
- nginx error-log diff for the v2 window (last v1-window check at ~18:07 showed 0 × 5xx and 0 × fatal for the 5 domains, but that predates the v2 deploy)

## 6. Discrepancies (precise)

1. **Briefed HEAD is stale.** Brief says `c21bfb3`; branch `v2.0` is `f7babd9` (+2 commits, 534 tests). Server deployed code is a mix: `SpamChecker`/`Waf` = `f7babd9`, `RequestData` = `c21bfb3`.
2. **CI was red at the briefed HEAD.** Run 41687281061 (`c21bfb3`) failed the coverage gate at 76.81 % lines / 65.31 % methods vs 95/90. Green only from `4b337b5`/`f7babd9`.
3. **Coverage standard was lowered, not met.** Commit text: "coverage ratchet 88/72", "measured 89.5/73.4"; the documented/CI-named threshold was 95/90.
4. **`src/Data/RequestData.php` on the server ≠ GitHub `v2.0`** (missing XFF-priority fix, line 240).
5. **`waf.mode = block` is live on 6 sites while the reference configs say `monitor`** — only diff, 2 bytes per file; contradicts the "monitor first" rollout docs.
6. **Stale CI comment** at `c21bfb3`: `.gitignore` no longer ignores `composer.lock`, but `ci.yml` says it does. (Lock is tracked — the important part is correct.)
7. **Server PHP 8.5.12 build date says "Jun 29 2020"** (impossible for 8.5.12; custom/repackaged `/opt/php85` build). Version string is 8.5.12; carries over from the v1 audit.

## 7. Suggested remaining checks (in order, for whoever finishes)

1. `POST https://conbat.ru/php/task-add.php` curl UA → expect `400` + `X-Spam-Guard: blocked`; then browser UA incomplete → app error without the header.
2. WAF attack with a **non-fail2ban-matching** payload (SQLi/XSS in query, avoid `../`, `.env`, `/etc/passwd`): expect `403` + `X-WAF: blocked`, and `[waf] blocked …` in `/var/www/httpd-logs/conbat.ru.error.log`.
3. `POST https://batterywizard.ru/api/lead` with browser UA + spam keywords → `200 {"ok":true}`, plus a `spam` line in `var/log/sites/batterywizard.ru.jsonl`; check `journalctl -u bwo.service` for the `[waf]`/`[spam-guard]` line.
4. `https://conbat.ru/support/form.php` (no token) → `404 "Форма недоступна"`; spam POST with token + Origin → `400` + `X-Spam-Guard`.
5. Redeploy `src/Data/RequestData.php` from `f7babd9` (or confirm the XFF change is intentionally not shipped) and decide whether `waf.mode=block` on 6 sites is the intended state.

## 8. Evidence locations

Local (this run; temp, disposable):
`%TEMP%\spamqa2-20261103-204628\`
- `evidence-01-repo.txt`, `evidence-02-phpunit.txt`, `evidence-03-ci.txt`
- `evidence-live\*.hdr`, `evidence-live\*.body` (7 GET requests incl. headers)
- `raw\` (GitHub raw copies used for hash comparison), `server-RequestData.php`, `server-*.php` config copies

Server: `/root/spamchecker-qa-v2/QA-V2-REPORT.md` (this file).
