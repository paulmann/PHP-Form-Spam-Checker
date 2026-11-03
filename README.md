# PHP Form Spam Checker

[![PHP](https://img.shields.io/badge/PHP-8.5.12-8892bf.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Paulmann/PHP-Form-Spam-Checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulmann/PHP-Form-Spam-Checker/actions/workflows/ci.yml)

**A layered, dependency-free spam checker for any PHP form.** Drop it into a plain
`mail()` handler, a custom CMS, a legacy portal or a non-PHP application
(Node, Go, Python) through the CLI/HTTP bridge — with no captcha, no external
API and no runtime Composer dependencies.

Every verdict carries evidence: which checks fired, with which scores, and why.

> **Документация на русском:** [README.ru.md](README.ru.md)

---

## Why another spam checker

CAPTCHAs punish visitors and still lose to LLM-driven form spam. Cloud APIs add
a network round-trip, a privacy question and a billing dependency to every
submission. This library stays local: nine cheap heuristics run first, the
payload is inspected for injection and spam signatures, and rate limiting is
durable across PHP-FPM workers. A form handler gets one boolean answer and a
human-readable reason trail.

## Features

| Layer | Check | What it catches |
|---|---|---|
| Honeypot | `honeypot` | Bots that fill hidden fields |
| Behaviour | `time_trap` | Submissions sent milliseconds after the page was rendered (HMAC-signed token, bound to the form) |
| Identity | `user_agent` | HTTP libraries, headless browsers, scanners, empty UA |
| Volume | `rate_limit` | Per-IP counters that survive worker restarts (file storage, flock) |
| Payload | `length` | Oversized fields and control characters |
| Injection | `sql_injection` | `UNION SELECT`, `DROP TABLE`, tautologies, time-based probes |
| Injection | `xss` | Script tags, event handlers, `javascript:` URIs, encoded payloads |
| Content | `links` | Link floods, URL shorteners, obfuscated `hxxp://` links |
| Content | `keywords` | Configurable multilingual spam vocabulary and regexes |
| Contact | `email` | Broken addresses and disposable mailboxes |
| Content | `repetition` | Keyboard mashing, repeated words |
| Content | `language` | Mixed-script homoglyphs (off by default) |

Plus:

- **Signed time trap** — `FormProtector::fields()` renders a honeypot and HMAC token; tokens cannot be forged or replayed across forms.
- **Durable storage** — file-backed counters work on shared hosting without Redis/APCu; the interface allows a custom backend.
- **Evidence-rich verdicts** — `Verdict::reasons()`, per-check scores, JSON-serialisable results.
- **Privacy-first logging** — JSONL verdict log hashes IPs and redacts fields unless PII logging is explicitly enabled.
- **Non-PHP bridges** — `bin/spam-check` CLI and `public/check.php` HTTP endpoint.
- **Server-wide use** — one shared copy at `/var/www/lib/PHP-Form-Spam-Checker` with per-site configs and `off`/`shadow`/`enforce` modes.

## Requirements

- PHP **8.5.12** (tested; compatible with the 8.5 branch)
- `ext-mbstring`, `ext-json`
- No runtime Composer dependencies

## Installation

### Composer

```bash
composer require paulmann/php-form-spam-checker
```

### Plain copy

Copy the repository somewhere readable by PHP and include `autoload.php`:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/autoload.php';
```

## Quick start: plain PHP form

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verdict = $protector->verifyRequest('contact');

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Заявка отклонена антиспам-проверкой.');
    }

    // ... send the e-mail
}
?>
<form method="post">
    <?= $protector->fields('contact') /* honeypot + signed time token */ ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Without the time trap (e.g. a cached page), disable it in the configuration and
keep the rest of the pipeline.

## Integration modes

### 1. Inside PHP

Directly construct `SpamChecker` (see above) or use the shared-module guard:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

The guard is configuration-driven (`config/sites/<host>.php`) and supports
`off` / `shadow` / `enforce`. See [docs/INTEGRATION.md](docs/INTEGRATION.md).

### 2. From Node / Go / Python (CLI bridge)

```bash
php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64_JSON
```

Output is one JSON object on STDOUT:

```json
{"form":"register","status":"spam","score":100,"reasons":["honeypot: honeypot field filled: website"],"checks":[...]}
```

Exit codes: `0` clean, `1` suspicious, `2` spam, `3` error. STDOUT stays clean
for `JSON.parse`. See [examples/node/bridge.mjs](examples/node/bridge.mjs).

### 3. Over HTTP (endpoint)

Deploy `public/check.php` and POST `{"form":..., "fields":{...},
"context":{"ip":...,"userAgent":...}}`. Protect it with `endpoint.key` and the
`X-Spam-Checker-Key` header.

## Server-wide deployment (one copy, many sites)

The recommended production layout is a single shared module:

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── src/            # library
├── bin/spam-check  # CLI bridge
├── integrations/   # guard.php, auto-prepend.php
├── config/sites/   # per-host configuration
├── var/sites/      # per-host counters
└── var/log/        # per-host verdict logs
```

Add one line to a site's form handler:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

and create `config/sites/<host>.php`:

```php
<?php
return [
    'site' => 'example.ru',
    'mode' => 'shadow',            // off | shadow | enforce
    'form' => 'contact',
    'match' => ['#^/feedback\.php#'],
    'skip'  => ['#^/admin#', '#^/auth#'],
    'config' => [
        'rate_limit' => ['max' => 8, 'window' => 900],
        'links' => ['max' => 2],
    ],
];
```

Start in `shadow` (log-only), review `var/log/sites/<host>.jsonl`, then switch
to `enforce`. `deploy/install-shared.sh` lays out the module with correct owners
and permissions.

## Configuration

A PHP array (returned from a file) or JSON. Every key is optional; defaults are
safe. The most useful knobs:

| Key | Default | Meaning |
|---|---|---|
| `thresholds.spam` | `60` | score at which a submission is spam |
| `thresholds.suspicious` | `30` | score at which it becomes suspicious |
| `time_trap.secret` | — | HMAC secret (required when the time trap is enabled) |
| `rate_limit.max` / `window` | `8` / `900` | requests per IP per window |
| `keywords.words` | RU+EN starter list | spam vocabulary |
| `links.max` | `2` | links allowed in the whole message |
| `email.disposable_domains` | ~70 domains | extra throwaway domains |
| `storage.path` | temp dir | counter storage |
| `log.path` | — | JSONL verdict log |
| `log.pii` | `false` | store raw IP and field samples |
| `forms.<id>` | — | per-form overrides |

Full reference: [docs/CONFIG.md](docs/CONFIG.md). Check semantics:
[docs/CHECKS.md](docs/CHECKS.md).

## Testing

```bash
composer install
composer test              # PHPUnit: 175 tests, 449 assertions
composer lint              # php -l over src, tests, bin
```

CI runs the suite on PHP 8.5.12 and 8.5 with strict warnings, risky-test and
deprecation gates.

## Security

- No network calls, no `eval`, no shell.
- The time-trap token is HMAC-SHA-256, constant-time compared, bound to the form id.
- The HTTP endpoint refuses non-POST requests, enforces a body limit and an optional shared key.
- Logging is privacy-preserving by default.
- Report vulnerabilities per [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Paulmann
