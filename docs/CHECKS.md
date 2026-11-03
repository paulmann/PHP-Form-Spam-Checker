# Check semantics

Each check returns a `FormSpamChecker\Data\CheckOutcome`:

```php
CheckOutcome(
    string $check,          // stable snake_case name, used in logs
    CheckStatus $status,    // spam | ham | uncertain | error
    int $score = 0,         // 0..100, capped sum decides Suspicious/Spam
    string $reason = '',    // human-readable, appears in Verdict::reasons()
    array $evidence = [],   // structured proof for the log
)
```

Statuses:

| Status | Meaning | Score |
|---|---|---|
| `spam` | hard verdict, ignores the numeric total | stored as evidence |
| `ham` | no hard verdict; a **positive** score is a suspicion signal | added to the total |
| `uncertain` | not enough data | contributes 0 |
| `error` | the check failed; the pipeline fails open | contributes 0 |

The pipeline sums the scores (capped at 100) and compares them with
`thresholds.spam` (default 60) / `thresholds.suspicious` (default 30). Any
`spam` outcome makes the whole submission spam. Design rule: hard verdicts are
reserved for evidence that cannot occur in a legitimate message; everything
debatable is point-based.

## Pipeline order

`SpamChecker::defaultChecks()` registers, in order:

```text
 1 honeypot           7  links              13 js_challenge      (behavioural)
 2 time_trap          8  keywords           14 abuseipdb         (network)
 3 user_agent         9  email              15 dnsbl             (network)
 4 rate_limit        10  repetition         16 spf               (network)
 5 length            11  language           17 dmarc             (network)
 6 sql_injection     12  dynamic_honeypot   18 bayes
```

Cheap local checks run first. `pipeline.stop_on_spam` (default `true`) stops the
run on the first hard `spam`, which saves AbuseIPDB quota and DNS lookups. A
check that throws is recorded as `error` and the pipeline continues.

## Local checks

### honeypot

A field hidden with CSS. A human never sees or fills it; a bot walking the DOM
does. Any non-empty value is a hard spam verdict.

- **False positives:** password managers occasionally fill hidden fields. Keep
  the honeypot name unremarkable (`website`) and use `autocomplete="off"`.
- **Config:** `honeypot.fields`, `honeypot.score` (100).

### dynamic_honeypot

2.0 behavioural layer. The field name is derived from the form id and the
current hour bucket:

```text
_hp_ + substr(hmac_sha256(secret, "formId|hourBucket"), 0, 12)
```

The current and the previous bucket are accepted (a form rendered at 12:59 and
submitted at 13:00 is legitimate). A filled expected field is a hard spam
verdict. A submission that posts **neither** expected field is suspicious
(`behavioral.honeypot.missing_score`, default 10): a browser always posts the
rendered form, a blind bot posts only its own fields.

- Dynamic mode is on by default (`behavioral.honeypot.dynamic = true`) but the
  check is registered only when a ≥ 16-character secret is configured
  (`behavioral.honeypot.secret`, falling back to `time_trap.secret`).
- With `dynamic = false` the static list is checked instead
  (`behavioral.honeypot.static`, falling back to 1.x `honeypot.fields`): a
  filled field is hard spam, a missing one is not suspicious — static names are
  public knowledge.
- A short secret is a configuration `error` (fail open).
- **False positives:** clients that strip all hidden inputs before posting.
  Keep `missing_score` low; never post-process forms in a way that drops fields.

### time_trap

A form rendered at T0 receives a signed token with T0. On submit, age =
now − T0.

| Situation | Result |
|---|---|
| token valid, age ≥ `min_seconds` | clean |
| age < `min_seconds` | Spam (a human cannot read a form in 500 ms) |
| token invalid / forged / other form | Spam |
| token older than `max_seconds` | Suspicious (cached page) |
| token missing, `require_token` | Suspicious |
| token missing, `require_token = false` | clean |

The token is `base64url(payload).base64url(HMAC-SHA-256)`, bound to the form id;
`hash_equals` prevents timing attacks. Use a ≥ 32-character random secret from
the environment.

- **False positives:** pages cached for longer than `max_seconds`; exclude those
  forms or raise the limit.
- **Config:** `time_trap.*` (`suspicious_score` 30, `spam_score` 80).

### user_agent

Case-insensitive substring match against a table of automation markers
(HTTP libraries, headless browsers, scanners). Empty UA is suspicious unless
`allow_empty` is enabled.

- **False positives:** a legitimate integration posting with `curl` — add an
  allow rule upstream (known IP) or extend `extra_blocklist` and handle it at
  the application level instead of disabling the check.
- **Config:** `user_agent.*` (empty 40, blocked 100).

### rate_limit

Increments a per-IP counter in durable storage; exceeding `max` inside
`window` seconds is a hard spam verdict. Counters are per form unless
`per_form = false`.

- **False positives:** shared corporate NAT and retries. Keep `max` above the
  real retry count (default 8/15 min) and set `per_form` for busy forms.
- **Config:** `rate_limit.max` 8, `window` 900, `score` 100.

### length

- field longer than `max` (5000) → suspicious (`score` 30);
- longer than `hard_max` (20000) → hard spam;
- NUL and control characters → hard spam.

- **False positives:** legitimate long messages; raise `length.max` for a form
  that accepts long descriptions.

### sql_injection

Strong signatures (UNION SELECT, DROP TABLE, SLEEP(), information_schema,
tautologies) are hard spam. Weak fragments ("select … from") are suspicious
only.

- **False positives:** an engineer describing a query. Weak patterns are
  intentionally low-scoring (40); strong patterns are 100.
- **Config:** `sql_injection.spam_score`, `suspicious_score`.

### xss

Script tags, iframes, event handlers, `javascript:`/`vbscript:`, `document.*`
access are hard spam. Encoded payloads (`&#60;script&#62;`, `%3Cscript`) are
suspicious.

- **False positives:** a user pasting HTML e-mail content; adjust the threshold
  or disable the weak patterns for that form.
- **Config:** `xss.spam_score` (100), `suspicious_score` (45).

### links

Counts `http(s)://`, `www.` links, shortener hosts and obfuscated spellings
(`hxxp://`, `site [.] ru`).

- more than `max` links → `score_per_extra` each;
- shortener → `shortener_score`;
- obfuscated → `obfuscated_score`.

- **False positives:** support requests quoting several URLs. Set `links.max`
  per form or disable the check for that form.
- **Config:** `links.max` 2, `score_per_extra` 15, `shortener_score` 35,
  `obfuscated_score` 25.

### keywords

Multibyte, case-insensitive substring scoring over all non-excluded fields.
Explicit PCRE patterns are supported. Never a hard spam verdict — the pipeline
threshold decides.

- **False positives:** a B2B message mentioning "кредит" or "seo". Review the
  starter list and keep project-specific vocabularies short and precise.
- **Config:** `keywords.per_hit` 12, `max_score` 90, `scan_fields`.

### email

- invalid syntax → `invalid_score` (40) (usually caught by form validation first);
- disposable/throwaway domain → `disposable_score` (70) (suffix match, so
  `inbox.mailinator.com` is caught).

- **False positives:** a legitimate user of a privacy mail provider. Keep
  `disposable_score` below `thresholds.spam` if that risk matters, or add the
  provider to an allow path in the application.
- **Config:** `email.fields`, `email.disposable_domains`.

### repetition

Runs of one character (`min_run` 12) and words repeated `min_word_repeats` (4)
times.

- **False positives:** "Очень очень очень нужно" — rare; keep scores moderate
  (`score` 25, `max_score` 60).

### language

Words that mix Cyrillic and Latin letters (homoglyph evasion). Disabled by
default because brand names and transliterations sometimes mix alphabets.

- **Config:** `language.mixed_script_score` 20, `max_score` 40.

## Behavioural: JS challenge

`js_challenge` verifies the signed challenge token and the computed answer.

- The server issues a signed token carrying a challenge; the inline script
  computes `challenge * 7 + 3` and writes it into the hidden answer field.
- **Missing or invalid answer/token → suspicious** (`missing_score` 15), never
  a hard spam verdict: a bot without JS is suspicious, not proven spam, and a
  broken deployment must fail open.
- A short secret is an `error` (fail open).
- **False positives:** NoScript users, strict CSP that blocks the inline script,
  forms rendered by a different process than the one verifying. Render the
  fields with `FormProtector::fields()` (it emits the script) and, with a CSP,
  allow-list the inline script by hash:

  ```php
  $hash = (new \FormSpamChecker\Behavioral\JsChallenge($config))->inlineScriptHash('contact');
  header("Content-Security-Policy: script-src 'self' " . $hash);
  ```

- **Config:** `behavioral.js_challenge.*` (`enabled` false, `field` `_js`,
  `missing_score` 15, `max_age` 86400).

## Network checks

Network checks are registered last and only when `enabled` is true. They never
run when the needed data is missing (no IP, private IP, no API key, no model),
and they fail open.

### abuseipdb

Asks the AbuseIPDB v2 `check` endpoint for the client IP's
`abuseConfidenceScore`.

| Situation | Result |
|---|---|
| check disabled / no API key / no valid public IP | `uncertain`, no network |
| cached answer for this IP | cached outcome (default 6 h) |
| score ≥ `threshold` (90) | hard **spam**, score = confidence |
| score < `threshold` | `ham`, 0, evidence with the score |
| HTTP 429 | `uncertain`; `Retry-After`/`X-RateLimit-Reset` stored; later lookups back off without network |
| transport error / HTTP 5xx | counts as a breaker failure → `uncertain` (or `error` with `fail_open = false`) |
| `circuit_breaker.failures` (3) failures in a row | breaker opens for `cooldown` (300 s): fast `uncertain` |
| first successful HTTP response | breaker closes |

The clock comes from `RequestData::timestamp()` (`now`), never `time()`, so
tests are deterministic. Private, reserved and loopback addresses are never
sent to the API.

- **Privacy / setup:** the client IP is transmitted to AbuseIPDB. The API key is
  a secret: keep it in the environment, never in a repository.
- **False positives:** a shared NAT IP with old abuse reports. Raise
  `threshold` per form, or leave the check disabled.
- **Config:** `abuseipdb.*` (see [docs/CONFIG.md](CONFIG.md)).

### dnsbl

Reverses the client IP and queries every configured DNSBL zone
(`zen.spamhaus.org`, `bl.spamcop.net` by default).

- IPv4 `1.2.3.4` → `4.3.2.1.<zone>`; IPv6 is expanded to 32 nibbles and
  reversed (RFC 3596).
- An answer inside `127.0.0.0/24` is a listing → hard **spam** with
  `dnsbl.hit_score` (100).
- Zones are queried in order; the first hit wins.
- A resolver that returns empty answers for every zone yields `ham`: a broken
  resolver must not punish a submission.
- Answers are cached by `CachedResolver` for `spf.dns_ttl` (3600 s minimum);
  `dnsbl.cache_ttl` documents the intended TTL.
- **False positives:** shared NAT. A listing is a hard verdict, so a whole
  office can be blocked; `dnsbl.hit_score` only changes the reported score, not
  the hard status. The practical levers are enabling DNSBL only for high-value
  forms and keeping the zone list to curated blocklists.
- **Config:** `dnsbl.*`.

### spf

Asks a domain-level question, not a sender question: **does the domain claimed
in the e-mail field publish a usable SPF policy?**

- It does **not** validate that the visitor is an authorised sender (the
  visitor's IP is not the sending MTA; `fail` for a legitimate `gmail.com`
  address is normal).
- No `v=spf1` record, several records, or `permerror` →
  `spf.missing_score` (10) suspicion.
- A usable policy → `ham`, score 0; `pass`/`fail`/`softfail`/`neutral` are
  recorded as evidence only.
- No usable e-mail address in `spf.fields` → `uncertain`.
- **False positives:** small domains without SPF. Keep the score low (10) or
  disable for consumer-facing forms.
- **Config:** `spf.fields`, `missing_score`, `lookup_limit`.

### dmarc

Reads `_dmarc.<domain>` and classifies the policy:

| Policy | Result |
|---|---|
| `p=quarantine` / `p=reject` | `ham`, 0 |
| `p=none` | suspicion `dmarc.weak_policy_score` (5) |
| missing / several records / invalid `p=` | suspicion `dmarc.missing_score` (10) |
| no usable e-mail address | `uncertain` |

A DMARC policy does not describe the submitting visitor, so this check never
returns hard spam.

### dkim

`dkim` configuration exists (`enabled`, `required`) and is **planned in this
release**: there is no `FormSpamChecker\Check\DkimCheck` class in the 2.0 tree
yet. The section is accepted and ignored so a config can be prepared in
advance. Do not rely on DKIM until the check is listed in `defaultChecks()`.

### bayes

Naive Bayes over the user content (technical fields excluded).

- Tokeniser: lower-cased Unicode words, ≥ 2 characters, with bigrams
  (`FormSpamChecker\Bayes\UnicodeTokenizer`), per-document caps.
- Scoring: Laplace smoothing, class priors from document counts,
  `P(spam) = 1 / (1 + exp(-ln odds))`, clamped to `[0.01, 0.99]`; an untrained
  model returns 0.5.
- Below `bayes.min_documents` (20) the check is `uncertain` (abstains).
- `probability >= bayes.threshold` (0.92) → `score = round(probability *
  score_scale)` (max 100); by default this is a **suspicion**, not a hard
  verdict. `bayes.hard = true` turns it into a hard spam verdict.
- The model is trained out of process:

  ```bash
  php bin/spam-train --config=/etc/spam.php \
      --ham=/etc/spam/ham.txt --spam=/etc/spam/spam.txt
  php bin/spam-train --config=/etc/spam.php --stats
  php bin/spam-train --config=/etc/spam.php --reset   # drop the model
  ```

  Training files: one document per line; blank lines and `#` comments skipped.
- **Privacy note:** the model stores token counts only (no source documents),
  under `cache`/`bayes.storage_path`; training data never leaves the machine.
- **False positives:** too few or unrepresentative training documents; the
  model overfits. Keep the ham set large and recent, retrain after vocabulary
  drifts, and keep `bayes.hard` false unless you review the model.
- **Config:** `bayes.*` (see [docs/CONFIG.md](CONFIG.md)).

## WAF rules vs form checks

The WAF has its own rule set over the whole request and its own configuration
(`waf.rules.<name>`, see [docs/WAF.md](WAF.md)). Both layers can be active at
once; they answer different questions:

| | Form checks | WAF rules |
|---|---|---|
| Scope | the form submission | every HTTP request |
| Output | score + hard verdict for the submission | block / allow the request |
| Response | application decides (400, moderation, …) | guard answers 403 (or monitor-logs) |
| SQLi/XSS | also detects in message fields, lower precision | high-precision signatures, request-level |
| Skip lists | none (form-level config) | admin/auth paths never inspected |

A WAF block happens **before** the form handler, so the form checks never see
the request. Keep the WAF in `monitor` first when you add it to a form that is
already protected by the form checks.

## Writing a custom check

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

Register it either explicitly:

```php
$checks = [...\FormSpamChecker\SpamChecker::defaultChecks($config, $storage), new MyCheck()];
$checker = new \FormSpamChecker\SpamChecker($config, $storage, $checks);
```

…or append immutably where you own the pipeline:

```php
use FormSpamChecker\Pipeline\SpamPipeline;

$pipeline = (new SpamPipeline($checks))->add(new MyCheck());
$verdict = $pipeline->process($request, $config);
```

A check that throws is caught by the pipeline and recorded as
`check error (fail open): <message>` — a broken check never blocks a form.

Custom WAF rules implement `FormSpamChecker\Waf\RuleInterface` (or extend
`AbstractRule`) and are passed to `new Waf($config, $rules, $logger)`.
