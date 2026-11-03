# Check semantics

Each check returns a `CheckResult` with a status, a score (0–100) and a reason.
The pipeline sums scores (capped at 100) and compares them with
`thresholds.spam` / `thresholds.suspicious`. A check that returns `Status::Spam`
makes the whole submission spam regardless of the numeric total.

Design rule: hard checks are reserved for evidence that cannot occur in a
legitimate message. Everything debatable is point-based.

## honeypot

A field hidden with CSS. A human never sees or fills it; a bot walking the DOM
does. Any non-empty value is a hard Spam verdict.

- **False positives:** password managers occasionally fill hidden fields. Keep
  the honeypot name unremarkable (`website`) and use `autocomplete="off"`.
- **Config:** `honeypot.fields`, `honeypot.score`.

## time_trap

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

## user_agent

Case-insensitive substring match against a table of automation markers
(HTTP libraries, headless browsers, scanners). Empty UA is suspicious unless
`allow_empty` is enabled.

- **False positives:** a legitimate integration posting with `curl` — add an
  allow rule upstream (known IP) or extend `extra_blocklist` and handle it at
  the application level instead of disabling the check.

## rate_limit

Increments a per-IP counter in durable storage; exceeding `max` inside
`window` seconds is a hard Spam verdict. Counters are per form unless
`per_form = false`.

- **False positives:** shared corporate NAT and retries. Keep `max` above the
  real retry count (default 8/15 min) and set `per_form` for busy forms.

## length

- field longer than `max` → suspicious points;
- longer than `hard_max` → hard Spam;
- NUL and control characters → hard Spam.

- **False positives:** legitimate long messages; raise `length.max` for a form
  that accepts long descriptions.

## sql_injection

Strong signatures (UNION SELECT, DROP TABLE, SLEEP(), information_schema,
tautologies) are hard Spam. Weak fragments ("select … from") are suspicious
only.

- **False positives:** an engineer describing a query. Weak patterns are
  intentionally low-scoring.

## xss

Script tags, iframes, event handlers, `javascript:`/`vbscript:`, `document.*`
access are hard Spam. Encoded payloads (`&#60;script&#62;`, `%3Cscript`) are
suspicious.

- **False positives:** a user pasting HTML e-mail content; adjust the threshold
  or disable the weak patterns for that form.

## links

Counts `http(s)://`, `www.` links, shortener hosts and obfuscated spellings
(`hxxp://`, `site [.] ru`).

- more than `max` links → `score_per_extra` each;
- shortener → `shortener_score`;
- obfuscated → `obfuscated_score`.

- **False positives:** support requests quoting several URLs. Set `links.max`
  per form or disable the check for that form.

## keywords

Multibyte, case-insensitive substring scoring over all non-excluded fields.
Explicit PCRE patterns are supported. Never a hard Spam verdict — the pipeline
threshold decides.

- **False positives:** a B2B message mentioning "кредит" or "seo". Review the
  starter list and keep project-specific vocabularies short and precise.

## email

- invalid syntax → `invalid_score` (usually caught by form validation first);
- disposable/throwaway domain → `disposable_score` (suffix match, so
  `inbox.mailinator.com` is caught).

- **False positives:** a legitimate user of a privacy mail provider. Keep
  `disposable_score` below `thresholds.spam` if that risk matters, or add the
  provider to an allow path in the application.

## repetition

Runs of one character (`min_run`) and words repeated `min_word_repeats` times.

- **False positives:** "Очень очень очень нужно" — rare; keep scores moderate.

## language

Words that mix Cyrillic and Latin letters (homoglyph evasion). Disabled by
default because brand names and transliterations sometimes mix alphabets.

## Writing a custom check

```php
final class MyCheck implements FormSpamChecker\CheckInterface
{
    public function name(): string { return 'my_check'; }

    public function check(FormSpamChecker\Submission $submission): FormSpamChecker\CheckResult
    {
        if ($submission->value('phone') === '') {
            return FormSpamChecker\CheckResult::suspicious('my_check', 20, 'phone is required');
        }

        return FormSpamChecker\CheckResult::clean('my_check');
    }
}

$checker = new SpamChecker($config, null, [...SpamChecker::defaultChecks($config, $storage), new MyCheck()]);
```

A check that throws is caught by the pipeline and recorded as
`check error (fail open): <message>` — a broken check never blocks a form.
