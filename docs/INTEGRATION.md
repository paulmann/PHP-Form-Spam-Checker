# Integration guide

Five ways to use the checker, from simplest to most invasive. All of them share
one `FormSpamChecker\Config`, one verdict model and the same per-site
configuration file.

- [1. Inside a PHP form (library)](#1-inside-a-php-form-library)
- [2. Shared server module with per-site configuration](#2-shared-server-module-with-per-site-configuration)
- [3. Drop-in WAF for the whole site](#3-drop-in-waf-for-the-whole-site)
- [4. Non-PHP applications (CLI bridges)](#4-non-php-applications-cli-bridges)
- [5. HTTP endpoint](#5-http-endpoint)
- [Training the Bayesian model](#training-the-bayesian-model)
- [Testing an integration](#testing-an-integration)

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
    'time_trap' => ['enabled' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    'behavioral' => [
        'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    ],
]);

$checker = new SpamChecker($config);
$protector = new FormProtector($checker, $config);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $verdict = $protector->verify($_POST, 'contact', Context::fromGlobals());

    if ($verdict->isSpam()) {
        http_response_code(400);
        exit('Заявка отклонена антиспам-проверкой.');
    }

    // Suspicious verdicts are not blocked here on purpose: inspect
    // $verdict->reasons() and decide whether to add moderation.
}
?>
<form method="post">
    <?= $protector->fields('contact') /* honeypot + token + optional JS challenge */ ?>
    <input name="email" type="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Отправить</button>
</form>
```

Notes:

- Call `verify()` / `verifyRequest()` **before** sending e-mail or writing to a
  database.
- `FormProtector::fields()` must be inside the `<form>`.
- For a 2.0-native call, build `FormSpamChecker\Data\RequestData` yourself and
  pass it to `SpamChecker::checkRequest()`:

  ```php
  use FormSpamChecker\Data\RequestData;

  $request = RequestData::fromGlobals($_SERVER, $_POST, 'contact');
  $verdict = $checker->checkRequest($request);
  ```

- A check that throws is recorded as `error` and fails open; logging or network
  failures never break the form.

## 2. Shared server module with per-site configuration

Recommended when many sites on one server need the same protection and updates
must not touch every docroot.

Layout:

```text
/var/www/lib/PHP-Form-Spam-Checker/
├── autoload.php
├── src/
├── bin/spam-check          # form verdict for non-PHP back ends
├── bin/waf-check           # WAF verdict for non-PHP back ends
├── bin/spam-train          # Bayesian model training
├── integrations/guard.php  # form guard drop-in
├── integrations/waf.php    # WAF drop-in
├── integrations/auto-prepend.php
├── config/sites/<host>.php
├── var/sites/<host>/        # counters
└── var/log/                 # verdict logs: <host>.jsonl
```

Install / update (run as root):

```bash
deploy/install-shared.sh /path/to/checkout
deploy/init-site-state.sh example.ru www-example   # per-site state ownership
```

In every form handler add one line **before** the application reads the input:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

`guard.php` runs two layers, in order:

1. the **WAF** — only when `waf.enabled` is set in the site config it inspects
   the whole request (URI, query, body, headers, cookies, method, size);
2. the **form pipeline** (`off` / `shadow` / `enforce`).

Both layers pass through anything that does not match their config, and any
internal error fails open. A site that uses `guard.php` does not need to include
`integrations/waf.php` as well — the firewall is already part of the guard.

Rejected submissions can be recovered from the registry: see [REJECTED-FORMS.md](REJECTED-FORMS.md).

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
        'behavioral' => [
            'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
        ],
        'log' => ['enabled' => true],
    ],
];
```

Rollout:

1. `mode = shadow` for 1–3 days. Every checked submission is logged with its
   verdict; the site behaves exactly as before.
2. Review `var/log/<host>.jsonl`: false positives are visible with the
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

`evaluateFor()` never terminates the script; it ignores `mode` (it always
evaluates) and returns the verdict for the caller to handle.

### Global installation with auto_prepend_file

If a site has dozens of handlers, add
`/var/www/lib/PHP-Form-Spam-Checker/integrations/auto-prepend.php` as
`auto_prepend_file` in that site's PHP-FPM pool and set `'auto' => true` inside
the site's `config` array. The form guard then runs only for URIs that match
`match`, so static pages and admin panels pay nothing.

The WAF layer inside `auto-prepend.php` runs **independently of the legacy
`auto` flag**: when `waf.enabled` is set, the firewall protects every request
while the form pipeline stays limited to the form endpoints. Do not enable it
for pools that serve heavy API traffic without reviewing `match`/`skip` and
`waf_match` first.

## 3. Drop-in WAF for the whole site

The WAF protects every HTTP request, not just form posts. Both layers live in
the same module and can be deployed in two ways:

- **`integrations/guard.php`** is the form guard and already runs the WAF first
  when `waf.enabled` is set — use it when the site has a form handler to edit;
- **`integrations/waf.php`** loads the firewall alone — use it for a site that
  has no form guard (or wants the firewall at a single front controller).

Load **one** of them per request. Requiring `waf.php` on top of `guard.php`
would inspect the request twice. Both read the same `config/sites/<host>.php`
(`waf` section inside `config`, plus optional top-level keys):

```php
// config/sites/example.ru.php — enable the WAF in monitor mode first
return [
    'site' => 'example.ru',
    'mode' => 'enforce',
    'waf_mode' => 'monitor',              // off | monitor | block
    'waf_response' => 'auto',             // auto | json | html | silent
    'config' => [
        'waf' => [
            'enabled' => true,
            'mode' => 'monitor',
            'rules' => ['ip_reputation' => false, 'rate_limit' => false],
        ],
    ],
];
```

```php
// firewalled site without a form guard:
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';

// site with forms — the guard runs WAF + form pipeline, one include:
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

A blocked request never reaches the form pipeline. Rollout, rules and response
behaviour: [docs/WAF.md](WAF.md).

## 4. Non-PHP applications (CLI bridges)

### Form verdict: `bin/spam-check`

```bash
php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64_JSON
```

STDOUT is one JSON object; exit codes: `0` clean, `1` suspicious, `2` spam,
`3` error.

```json
{"form":"register","status":"spam","score":100,
 "reasons":["honeypot: honeypot field filled: website"],
 "checks":[{"check":"honeypot","status":"spam","score":100,
            "reason":"honeypot field filled: website","evidence":{"field":"website"}}]}
```

2.0 note: the top-level shape and exit codes are unchanged from 1.x, but
`checks[].status` is now `spam|ham|uncertain|error` (1.x used
`clean|suspicious|spam`). See [docs/MIGRATION-1-to-2.md](MIGRATION-1-to-2.md).

### WAF verdict: `bin/waf-check`

```bash
php bin/waf-check --config=/etc/spam.php \
  --json='{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
           "headers":{"host":"example.ru","content-type":"application/json"},
           "body":"{}","fields":{},"form":"lead"}'
```

Output: `{"blocked":bool,"status":"clean|suspicious|blocked","score":int,
"findings":[…],"reasons":[…]}`; exit codes `0` allow, `2` block, `3` error;
a disabled WAF answers `status: "disabled"`. Always send `host` and
`content-type` headers — the `protocol` rule scores their absence (softly).
Full format: [docs/WAF.md](WAF.md#cli-bridge-for-non-php-back-ends).

### Node bridge

`examples/node/bridge.mjs` is the pattern used in production for the Astro
site; it wraps both bridges:

```js
import { checkSpam } from "./bridge.mjs";

const verdict = await checkSpam("register", fields, {
  ip: request.ip,
  userAgent: request.headers["user-agent"],
  page: "/register/",
});

if (verdict.status === "spam") {
  // reject generically
}
```

```bash
node examples/node/bridge.mjs register
```

Rules for a bridge:

- treat `status = error` (and a missing answer) as **fail open**: process the
  form normally, log the error;
- keep the timeout short (2–5 s); the checker is local and CPU-bound;
- STDOUT is JSON only; diagnostics go to STDERR and exit code 3.

### PHP caller example

```php
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

## 5. HTTP endpoint

`public/check.php` accepts `POST` JSON and returns the verdict:

```bash
curl -s -X POST https://example.ru/check.php \
  -H 'Content-Type: application/json' \
  -H 'X-Spam-Checker-Key: ...' \
  -d '{"form":"contact","fields":{"email":"a@b.c"},"context":{"ip":"203.0.113.1","userAgent":"..."}}'
```

Response: `{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}`.
HTTP 400 for invalid JSON, 403 for a wrong key, 405 for non-POST, 413 for a too
large body, 500 for a checker error.

The endpoint is stateless and safe on an internal interface or localhost. It
does not echo submitted fields back. Configure the shared key in
`endpoint.key` and pass it in `X-Spam-Checker-Key` (constant-time compared).

## Training the Bayesian model

`bayes` is off by default and abstains until the model has
`bayes.min_documents` (20) documents:

```bash
php bin/spam-train --config=/etc/spam.php \
    --ham=/etc/spam/ham.txt --spam=/etc/spam/spam.txt

php bin/spam-train --config=/etc/spam.php \
    --text-spam="casino bitcoin payday loan" \
    --text-ham="нужен отчёт по поверке прибора"

php bin/spam-train --config=/etc/spam.php --stats
php bin/spam-train --config=/etc/spam.php --reset
```

Training data is plain text: one document per line, blank lines and `#`
comments skipped, several files comma-separated. The model keeps token counts
only (no source documents) and is stored through the configured cache
(`bayes.storage_path` namespaces the model key). Training is offline; nothing
leaves the machine.

There is no label feedback loop from the pipeline: retrain after collecting new
ham/spam samples, and keep `bayes.hard` false until you have reviewed the model
on real traffic.

## Testing an integration

1. Unit-test the wiring with `storage.driver = memory`, `cache.driver = memory`
   and a stub context (no network, no filesystem).
2. Send a honeypot payload: expect spam, no e-mail sent.
3. Send a clean payload: expect clean and one normal lead.
4. Check the verdict log line for both.
5. In `shadow` mode verify that the application still processes spam payloads
   (no regression) before switching to `enforce`.
6. For the WAF, run it in `monitor` for a day and compare the logged verdicts
   with the form verdicts before enabling `block`.

Run the shipped `examples/` against a local or staging copy only: they use demo
secrets and the system temp directory, and must never be pointed at a production
site's config or state.

## Fail2Ban and auto-ban

`integrations/guard.php` runs the WAF (when enabled) and then the form pipeline.
Both layers report hard events to `fail2ban.log_path` (when `fail2ban.enabled`)
and feed the `autoban` counter (when `autoban.enabled`); the next request from a
banned IP is rejected by the `autoban` check with a hard SPAM verdict. See
`docs/CONFIG.md#fail2ban-and-auto-ban-21` for keys and `docs/WAF.md#fail2ban`
for the jail.
