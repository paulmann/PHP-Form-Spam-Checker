# Checks

Each check answers one question about the submission and returns a `FormSpamChecker\Data\CheckOutcome`.
The pipeline runs the checks in a fixed order, sums their scores and compares the sum with two
thresholds; a hard verdict short-circuits that arithmetic.

## The outcome contract

```php
CheckOutcome(
    string $check,          // stable snake_case name, used in logs
    CheckStatus $status,    // spam | ham | uncertain | error
    int $score = 0,         // 0..100, capped sum decides Suspicious/Spam
    string $reason = '',    // human-readable, appears in Verdict::reasons()
    array $evidence = [],   // structured proof for the log
)
```

Quote: `docs/CHECKS.md`, opening section.

| Status | Meaning | Score |
|---|---|---|
| `spam` | hard verdict, ignores the numeric total | stored as evidence |
| `ham` | no hard verdict; a **positive** score is a suspicion signal | added to the total |
| `uncertain` | not enough data — this means "not checked", not "clean" | contributes 0 |
| `error` | the check failed; the pipeline fails open | contributes 0 |

The pipeline sums scores, caps the sum at 100 and compares it with `thresholds.spam` (default 60)
and `thresholds.suspicious` (default 30). Any `spam` outcome makes the whole submission spam. The
design rule behind the split: hard verdicts are reserved for evidence that cannot occur in a
legitimate message, everything debatable is point-based (`docs/CHECKS.md`, Check semantics).

## Pipeline order

`SpamChecker::defaultChecks()` registers, in order (`docs/CHECKS.md`, Pipeline order):

```text
 1 honeypot           7  links              13 js_challenge      (behavioural)
 2 time_trap          8  keywords           14 abuseipdb         (network)
 3 user_agent         9  email              15 dnsbl             (network)
 4 rate_limit        10  repetition         16 spf               (network)
 5 length            11  language           17 dmarc             (network)
 6 sql_injection     12  dynamic_honeypot   18 bayes
```

Cheap local checks run first, and `pipeline.stop_on_spam` (default `true`) stops the run on the
first hard `spam`, which saves AbuseIPDB quota and DNS lookups. The 2.1 `autoban` check runs
*before* all of them: a banned IP is rejected before any other check runs (`README.md`, Fail2Ban
and auto-ban). A check that throws is recorded as `error` and the pipeline continues.

## Checks, defaults and scores

All scores are 0–100; "spam" means a hard verdict. The table reproduces `README.md`, section Check
modules and defaults, where the reference deployments may use a different value (that is marked).

| Layer | Check | Default | Score or effect |
|---|---|---|---|
| Behaviour | `honeypot` | on | filled hidden field → spam 100 |
| Behaviour | `dynamic_honeypot` | on when a ≥16-character secret is set | filled → spam 100; neither expected field posted → 10 |
| Behaviour | `time_trap` | off (needs a rendered secret) | too fast or forged → spam 80; missing/expired → 30 |
| Behaviour | `js_challenge` | off | missing or invalid answer → 15, never hard |
| Identity | `user_agent` | on | empty UA → 40; tool/marker UA → spam 100 |
| Volume | `rate_limit` | on, 8 requests / 900 s | exceeded → spam 100 |
| Firewall | `autoban` | off (reference deployments: on) | banned IP → spam 100, before any other check |
| Payload | `length` | on, max 5000 | too long → 30; above 20000 or control characters → spam 100 |
| Injection | `sql_injection` | on | strong signature → spam 100; weak → 40 |
| Injection | `xss` | on | script/handler → spam 100; encoded → 45 |
| Content | `links` | on, max 2 | extra link 15; shortener 35; obfuscated 25 |
| Content | `keywords` | on | 12 points per hit, max 90 |
| Contact | `email` | on | invalid 40; disposable 70 |
| Content | `repetition` | on | runs and repeats → 25, max 60 |
| Content | `language` | off | mixed scripts → 20, max 40 |
| Network | `abuseipdb` | off | confidence at or above the threshold → spam (score = confidence) |
| Network | `dnsbl` | off | listing → spam 100 |
| Domain | `spf` | off | no usable policy → 10 |
| Domain | `dmarc` | off | missing → 10; `p=none` → 5 |
| Model | `bayes` | off | `P(spam)` at or above 0.92 → score = `P × 100`, suspicious by default |

`dkim` is configured but not implemented in this release: the section is accepted and ignored, and
there is no DKIM check in `defaultChecks()` (`README.md`, Check modules and defaults;
`docs/CHECKS.md`, dkim).

## What each local check actually looks for

| Check | Signal | Chief false positive |
|---|---|---|
| `honeypot` | any value in a CSS-hidden field | password managers occasionally fill hidden fields |
| `dynamic_honeypot` | value in an hourly HMAC-derived field; the current and previous hour are accepted | clients that strip hidden inputs before posting |
| `time_trap` | age of a signed token against `min_seconds` (2) and `max_seconds` (604800) | pages cached for longer than `max_seconds` |
| `user_agent` | case-insensitive markers for HTTP libraries, headless browsers, scanners | a legitimate `curl` integration |
| `rate_limit` | per-IP counter in durable storage | shared corporate NAT and legitimate retries |
| `length` | field longer than 5000, 20000, or NUL/control characters | genuinely long messages |
| `sql_injection` | strong signatures hard, weak fragments 40 | an engineer describing a query |
| `xss` | script tags, handlers, `javascript:`, encoded payloads | a user pasting HTML e-mail content |
| `links` | more than 2 links, shortener hosts, `hxxp://` spellings | support requests quoting several URLs |
| `keywords` | multibyte substring scoring plus optional PCRE | a B2B message mentioning "credit" or "seo" |
| `email` | syntax, disposable-domain suffix match | a legitimate privacy-mail user |
| `repetition` | character runs and repeated words | emphasis in ordinary prose |
| `language` | Cyrillic and Latin letters inside one word | brand names and transliterations |

Semantics and tuning for each row are in `docs/CHECKS.md`, section Local checks; the scores above
come from `docs/CONFIG.md`, Full default tree.

## Network checks

Network checks are registered last, only when `enabled` is true, never run without the needed data
(no IP, private IP, no API key, no model), and all fail open (`docs/CHECKS.md`, Network checks).

### AbuseIPDB

| Situation | Result |
|---|---|
| disabled, no API key, or no valid public IP | `uncertain`, no network call |
| cached answer for this IP | cached outcome (default 6 h) |
| score at or above `threshold` | hard spam, score = confidence |
| score below `threshold` | `ham`, 0, confidence in evidence |
| HTTP 429 | `uncertain`; `Retry-After` stored and later lookups back off |
| transport error or HTTP 5xx | breaker failure → `uncertain` (or `error` with `fail_open = false`) |
| 3 consecutive failures | circuit opens for 300 s, fast `uncertain` |
| first successful HTTP response | circuit closes |

The library default `abuseipdb.threshold` is `90`; the 2.1 reference deployments set `100`, which
means only IPs whose confidence score is exactly 100 are treated as spam (`README.md`, AbuseIPDB
setup and Fail2Ban and auto-ban; `CHANGELOG.md`, `[2.1.0]` Added, Deployment guidance). Caching,
`max_age_days` (30) and the breaker limits are quoted from `docs/CONFIG.md`, Full default tree.

The client IP is sent to AbuseIPDB — the only form-related data that leaves the machine, and only
when the check is enabled (`SECURITY.md`, Network egress). Private, reserved and loopback addresses
are never sent (`docs/CHECKS.md`, abuseipdb).

### DNSBL, SPF, DMARC

- `dnsbl` reverses the client IP (IPv4 and IPv6 nibble form) and queries every configured zone
  (`zen.spamhaus.org`, `bl.spamcop.net` by default); an answer inside `127.0.0.0/24` is a listing
  and a hard spam with `dnsbl.hit_score` (100). A resolver that answers nothing for every zone
  yields `ham`: a broken resolver must not punish a submission (`docs/CHECKS.md`, dnsbl).
- `spf` and `dmarc` ask a domain-level question — does the domain claimed in the e-mail field
  publish a usable policy — not a sender question. A visitor's IP is not the sending MTA, so `fail`
  for a legitimate `gmail.com` address is normal; both checks only contribute a score and never
  produce a hard verdict (`docs/CHECKS.md`, spf and dmarc).

### Bayesian classifier

Off by default and abstains until the model has `bayes.min_documents` (20) documents. Above
`bayes.threshold` (0.92) the check scores `round(probability × score_scale)`, a suspicion unless
`bayes.hard` is set. The model stores token counts only, never the training documents, and training
is offline (`docs/CHECKS.md`, bayes):

```bash
php bin/spam-train --config=/etc/spam.php --ham=/etc/spam/ham.txt --spam=/etc/spam/spam.txt
php bin/spam-train --config=/etc/spam.php --stats
php bin/spam-train --config=/etc/spam.php --reset
```

There is no label feedback loop from the pipeline: retrain from collected samples and keep
`bayes.hard` false until the model has been reviewed on real traffic (`docs/INTEGRATION.md`,
Training the Bayesian model).

## Custom checks

A check implements `FormSpamChecker\Check\SpamCheckInterface` and returns `CheckOutcome`
(`docs/CHECKS.md`, Writing a custom check):

```php
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

final readonly class MyCheck implements SpamCheckInterface
{
    public function name(): string
    {
        return 'my_check';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if ($data->field('phone') === '') {
            return CheckOutcome::suspicious('my_check', 20, 'phone is required', [
                'field' => 'phone',
            ]);
        }

        return CheckOutcome::ham('my_check');
    }
}
```

Register it explicitly with the default pipeline, or append it immutably where you own the
pipeline:

```php
$checks = [...\FormSpamChecker\SpamChecker::defaultChecks($config, $storage), new MyCheck()];
$checker = new \FormSpamChecker\SpamChecker($config, $storage, $checks);
```

A check that throws is caught and recorded as `check error (fail open): <message>`. A new check
belongs in `Config::defaults()` and needs a positive fixture and a false-positive decoy (`AGENTS.md`,
Rules).

## WAF rules are a different layer

The form checks judge a submission; the WAF rules judge a whole HTTP request and answer block or
allow. A WAF block happens before the form handler, so form checks never see that request — keep
the WAF in `monitor` first when adding it to a form that already has form checks
(`docs/CHECKS.md`, WAF rules vs form checks). See [WAF](05-WAF).

## Next

- [WAF](05-WAF) — the request-level layer.
- [Configuration](03-Configuration) — where these scores are changed.
