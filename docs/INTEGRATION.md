# Integration guide

Three ways to use the checker, from simplest to most invasive. All three share
the same `FormSpamChecker\Config` and verdict model.

## 1. Inside a PHP form (library)

```php
<?php
declare(strict_types=1);

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;

require __DIR__ . '/vendor/autoload.php';

$config = Config::fromArray([
    'storage' => ['path' => __DIR__ . '/var/spam'],
    'log' => ['enabled' => true, 'path' => __DIR__ . '/var/spam/verdicts.jsonl'],
    'time_trap' => ['enabled' => true, 'secret' => getenv('SPAM_SECRET') ?: ''],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

$error = '';
$sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        $error = 'Заявка отклонена антиспам-проверкой.';
    } else {
        // send e-mail / write to DB
        $sent = true;
    }
}
?>
<form method="post" action="">
    <?= $protector->fields('contact') ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Notes:

- Call `verify()` **before** sending e-mail or writing to a database.
- `Suspicious` verdicts are not blocked here on purpose: inspect
  `$verdict->reasons()` and decide whether to add moderation.
- `FormProtector::fields()` must be inside the `<form>`.

## 2. Shared server module with per-site configuration

Recommended when many sites on one server need the same protection and updates
must not touch every docroot.

Layout:

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── autoload.php
├── src/
├── bin/spam-check
├── integrations/guard.php
├── config/sites/<host>.php
├── var/sites/<host>/        # counters
└── var/log/sites/<host>.jsonl
```

Install / update (run as root):

```bash
deploy/install-shared.sh /path/to/checkout
```

In every form handler add one line **before** the application reads the input:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

Create `config/sites/<host>.php`:

```php
<?php
return [
    'site' => 'example.ru',
    'mode' => 'shadow',                 // off | shadow | enforce
    'form' => 'contact',
    'response' => 'auto',               // auto | json | html | silent
    'match' => ['#^/feedback\.php#'],   // checked URIs (empty = any POST)
    'skip'  => ['#^/admin#', '#^/login#', '#^/api/internal#'],
    'config' => [
        'rate_limit' => ['max' => 8, 'window' => 900],
        'links' => ['max' => 2],
        'log' => ['enabled' => true],
    ],
];
```

Rollout:

1. `mode = shadow` for 1–3 days. Every checked submission is logged with its
   verdict; the site behaves exactly as before.
2. Review `var/log/sites/<host>.jsonl`: false positives are visible with the
   exact check and reason.
3. Tune `config` for the site, then switch `mode = enforce`.

In `enforce` mode a spam request receives HTTP 400 and the application never
runs. `response = silent` returns HTTP 200 with an empty body (useful to avoid
telling a bot that it was detected).

### Controller integration

When a framework owns the response, do not include `guard.php` (it would exit);
evaluate instead:

```php
require_once '/var/www/lib/PHP-Form-Spam-Checker/autoload.php';

$verdict = FormSpamChecker\Integration\FormGuard::evaluateFor(
    'example.ru',
    $_POST,
    $_SERVER,
    'contact',
);

if ($verdict->isSpam()) {
    return new JsonResponse(['ok' => false, 'error' => 'spam_detected'], 400);
}
```

This is the pattern used for the BatteryService support module: one call at the
single public-create choke point covers every site that embeds the form.

### Global installation with auto_prepend_file

If a site has dozens of handlers, add
`/var/www/lib/PHP-Form-Spam-Checker/integrations/auto-prepend.php` as
`auto_prepend_file` in that site's PHP-FPM pool and set `'auto' => true` inside
the site's `config` array. The guard then runs only for URIs that match
`match`, so static pages and admin panels pay nothing. Do not enable it for
pools that serve heavy API traffic without reviewing `match`/`skip` first.

## 3. Non-PHP applications (CLI bridge)

```php
// PHP CLI is the only interface; the caller language does not matter.
$payload = json_encode([
    'form' => 'register',
    'fields' => $fields,
    'context' => ['ip' => $ip, 'userAgent' => $ua, 'page' => '/register/'],
], JSON_UNESCAPED_UNICODE);

$base64 = base64_encode($payload);
$command = sprintf(
    '%s /var/www/lib/PHP-Form-Spam-Checker/bin/spam-check --form=register --base64=%s',
    escapeshellarg('/opt/php85/bin/php'),
    escapeshellarg($base64),
);
exec($command, $lines, $code);
$verdict = json_decode(implode('', $lines), true);

if ($verdict['status'] === 'spam') {
    // silently accept or return a generic error
}
```

A Node version is in `examples/node/bridge.mjs` and is the pattern used in
production for the Astro site:

```js
import { execFile } from "node:child_process";

function checkSpam(formId, fields, context) {
  const payload = JSON.stringify({ form: formId, fields, context });
  const base64 = Buffer.from(payload, "utf8").toString("base64");
  return new Promise((resolve) => {
    execFile("/usr/bin/php8.5", [
      "/var/www/lib/PHP-Form-Spam-Checker/bin/spam-check",
      `--form=${formId}`,
      `--config=/var/www/lib/PHP-Form-Spam-Checker/config/sites/batterywizard.ru.php`,
      `--base64=${base64}`,
    ], { timeout: 5000 }, (error, stdout) => {
      resolve(error && !stdout ? { status: "error" } : JSON.parse(stdout));
    });
  });
}
```

Rules for the bridge:

- Treat `status = error` as **fail open**: process the form normally, log the
  error.
- Keep the timeout short (2–5 s). The checker is local and CPU-bound.
- STDOUT is JSON only; diagnostics go to STDERR and exit code 3.

## HTTP endpoint

`public/check.php` accepts `POST` JSON and returns the verdict:

```bash
curl -s -X POST https://example.ru/check.php \
  -H 'Content-Type: application/json' \
  -H 'X-Spam-Checker-Key: ...' \
  -d '{"form":"contact","fields":{"email":"a@b.c"},"context":{"ip":"203.0.113.1","userAgent":"..."}}'
```

Response: `{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}`.
HTTP 400 for invalid JSON, 403 for a wrong key, 405 for non-POST, 413 for a too
large body.

## Testing an integration

1. Unit-test the wiring with `storage.driver = memory` and a stub context.
2. Send a honeypot payload: expect spam, no e-mail sent.
3. Send a clean payload: expect clean and one normal lead.
4. Check the verdict log line for both.
5. In `shadow` mode verify that the application still processes spam payloads
   (no regression) before switching to `enforce`.
