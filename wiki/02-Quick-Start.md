# Quick Start

Three steps: load a configuration, verify a submission before the application acts on it, render
the form fields. Everything else in this wiki adds protection around that shape.

## 1. Configuration file

A configuration is a PHP array returned from a file, a JSON document or an array passed to
`Config::fromArray()`. Every key is optional and unknown keys are preserved and ignored, so a
partial file is valid (`docs/CONFIG.md`, opening paragraph).

```php
<?php
declare(strict_types=1);

return [
    'storage' => ['path' => __DIR__ . '/var/spam'],
    'log' => ['enabled' => true, 'path' => __DIR__ . '/var/spam/verdicts.jsonl'],
    'time_trap' => ['enabled' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    'behavioral' => [
        'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    ],
];
```

The array above is quoted from `docs/INTEGRATION.md`, section 1; the same pattern appears in
`config/spam-checker.example.php`. Secrets must be at least 16 characters and the time trap
recommends 32 or more random characters; a short secret is a configuration error that fails open
(`SECURITY.md`, Time-trap and challenge tokens). The dynamic honeypot registers itself only when a
secret is configured, so the one `SPAM_CHECKER_SECRET` in the example serves both features.

## 2. Verify the submission

```php
<?php
declare(strict_types=1);

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require __DIR__ . '/vendor/autoload.php';

$config = Config::fromFile(__DIR__ . '/config/spam-checker.php');
$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Submission rejected by the anti-spam check.');
    }

    // ... send the e-mail
}
?>
<form method="post">
    <?= $protector->fields('contact') /* honeypot + signed token + optional JS challenge */ ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Send</button>
</form>
```

This is the `README.md` Quick start example with an English rejection message. Two ordering rules
matter more than the code: call `verify()` **before** sending e-mail or writing to a database, and
keep `FormProtector::fields()` **inside** the `<form>` element (`docs/INTEGRATION.md`, section 1).

`fields()` renders, in this order (`docs/MIGRATION-1-to-2.md`, `FormProtector::fields()` changed):

1. the honeypot — a dynamic HMAC-derived name when `behavioral.honeypot.dynamic` is on and a
   secret of at least 16 characters exists, otherwise the 1.x static `honeypot.fields` list;
2. the signed time-trap token when `time_trap.enabled`;
3. the JS challenge fields and inline script when `behavioral.js_challenge.enabled`.

## 3. Read the verdict

| Verdict | Meaning | Typical handling |
|---|---|---|
| `clean` | no signal above the suspicious threshold | process the form |
| `suspicious` | score at or above `thresholds.suspicious` | process, add moderation or a manual queue |
| `spam` | a hard verdict, or score at or above `thresholds.spam` | reject without telling the bot why |

Defaults are `thresholds.suspicious = 30` and `thresholds.spam = 60`; a hard spam outcome wins
regardless of the numeric total (`docs/CONFIG.md`, Full default tree; `docs/CHECKS.md`, Check
semantics). `$verdict->reasons()` returns the human-readable reasons and `$verdict->flagged()`
the outcomes that fired, so a moderation queue can show why.

A check that throws is recorded as `error` and the pipeline continues: a broken check never blocks
a form (`docs/CHECKS.md`, Check semantics).

## Probe from the command line

The same pipeline is available without a web request, which is the fastest way to check a
configuration (`AGENTS.md`, Use non-interactively):

```bash
printf '%s' "$PAYLOAD" | php bin/spam-check --config=/etc/spam.php --form=contact --stdin --json
```

STDOUT is one JSON object; exit codes are `0` clean, `1` suspicious, `2` spam, `3` error
(`docs/INTEGRATION.md`, section 4):

```json
{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}
```

Two cautions from the same document: always pass `--config=` (a missing configuration silently runs
on defaults) and read "empty" correctly — `uncertain` means "not checked", not "clean".

## HTTP endpoint

For a front end that cannot include PHP, `public/check.php` accepts `POST` JSON
(`docs/INTEGRATION.md`, section 5):

```bash
curl -s -X POST https://example.ru/check.php \
  -H 'Content-Type: application/json' \
  -H 'X-Spam-Checker-Key: ...' \
  -d '{"form":"contact","fields":{"email":"a@b.c"},"context":{"ip":"203.0.113.1","userAgent":"..."}}'
```

Response: `{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}`. Status codes
are `400` for invalid JSON, `403` for a wrong key, `405` for non-POST, `413` for a body over
`endpoint.max_body_bytes` (default 262144 bytes, `docs/CONFIG.md`) and `500` for a checker error.
The endpoint is stateless, does not echo submitted fields back, and compares the key in constant
time; keep it on an internal interface or localhost.

## Runnable examples

| Example | What it shows |
|---|---|
| `examples/plain-form.php` | the form above; run with `php -S 127.0.0.1:8080 examples/plain-form.php` |
| `examples/abuseipdb.php` | AbuseIPDB wiring (needs `ext-curl` and a key for live lookups) |
| `examples/bayes-train.php` | Bayesian training from a script |
| `examples/waf.php` | the WAF as a library |
| `examples/node/bridge.mjs` | a Node caller for both CLI bridges |

Run demos against a local or staging copy: they write to the system temp directory and must never
be pointed at a production site's configuration or state (`README.md`, Testing;
`docs/INTEGRATION.md`, Testing an integration).

## Next

- [Configuration](03-Configuration) — per-form overrides, storage, logging.
- [Checks](04-Checks) — what each verdict actually measured.
