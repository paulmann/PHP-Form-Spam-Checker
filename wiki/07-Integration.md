# Integration

Five ways to use the checker, from simplest to most invasive. All of them share one
`FormSpamChecker\Config`, one verdict model and the same per-site configuration file
(`docs/INTEGRATION.md`, introduction).

| Mode | When to use it |
|---|---|
| Library inside a PHP form | a single application you control |
| Shared server module with per-site configuration | many sites on one server, updates must not touch every document root |
| Drop-in WAF for the whole site | you want the request firewall without editing form handlers |
| Non-PHP applications (CLI bridges) | Node, Go, Python or Perl back ends |
| HTTP endpoint | a front end that can only make a POST request |

## 1. Inside a PHP form

Create `SpamChecker` and `FormProtector`, call `verify()` before the application acts on the
submission, and render `FormProtector::fields()` inside the form. The complete example is
[Quick Start](02-Quick-Start); the 2.0-native call builds `FormSpamChecker\Data\RequestData`
yourself and uses `SpamChecker::checkRequest()`:

```php
use FormSpamChecker\Data\RequestData;

$request = RequestData::fromGlobals($_SERVER, $_POST, 'contact');
$verdict = $checker->checkRequest($request);
```

Quote: `docs/INTEGRATION.md`, section 1. A check that throws is recorded as `error` and fails open,
so logging or network failures never break the form.

## 2. Shared server module with per-site configuration

The recommended shape when many sites on one server need the same protection
(`docs/INTEGRATION.md`, section 2):

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

Install once, then initialise per-site state as root:

```bash
deploy/install-shared.sh /path/to/checkout
deploy/init-site-state.sh example.ru www-example
```

A site gets one line in its form handler, **before** the application reads input:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

`guard.php` runs two layers in order: the WAF, only when `waf.enabled` is set in the site
configuration, and then the form pipeline with its `off` / `shadow` / `enforce` modes. Both pass
anything that does not match their configuration, and any internal error fails open. A site that
uses `guard.php` does not need `integrations/waf.php` as well (`docs/INTEGRATION.md`, section 2).

### Site configuration

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
        'behavioral' => [
            'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
        ],
        'log' => ['enabled' => true],
    ],
];
```

Quote: `docs/INTEGRATION.md`, section 2. The file is accepted by both guards, the CLI bridges and
`Config::fromFile()`; the guard defaults storage and logging into the module's `var/` tree unless the
site configuration sets them (`docs/CONFIG.md`, Shared-guard site configuration).

### Rollout

1. `mode = shadow` for one to three days. Every checked submission is logged with its verdict; the
   site behaves exactly as before.
2. Review `var/log/<host>.jsonl`: a false positive appears with the exact check and reason.
3. Tune `config` for the site, then switch `mode = enforce`.

In `enforce` mode a spam request receives HTTP 400 and the application never runs;
`response = silent` returns HTTP 200 with an empty body instead (`docs/INTEGRATION.md`, section 2).

### When a framework owns the response

Do not include `guard.php` there — it exits. Evaluate instead:

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

`evaluateFor()` never terminates the script; it ignores `mode` and always evaluates, returning the
verdict for the caller to handle (`docs/INTEGRATION.md`, Controller integration).

### Pool-wide installation

If a site has dozens of handlers, add `integrations/auto-prepend.php` as `auto_prepend_file` in that
site's PHP-FPM pool and set `'auto' => true` inside the site's `config` array. The form guard then
runs only for URIs that match `match`, so static pages and admin panels pay nothing. The WAF layer
inside `auto-prepend.php` runs independently of the legacy `auto` flag, so a pool can be firewalled
while the form pipeline stays limited to form endpoints — review `match`/`skip` and `waf_match`
before enabling it for a pool that serves heavy API traffic (`docs/INTEGRATION.md`, section 2).

## 3. Drop-in WAF for the whole site

Two includes exist and exactly one of them belongs in a request (`docs/INTEGRATION.md`, section 3):

- `integrations/guard.php` — form guard plus the WAF first when `waf.enabled` is set; use it when the
  site has a form handler to edit;
- `integrations/waf.php` — firewall only; use it when the site has no form guard, or wants the
  firewall at a single front controller.

A blocked request never reaches the form pipeline. Rules, rollout and response behaviour are in
[WAF](05-WAF).

## 4. Non-PHP applications (CLI bridges)

`bin/spam-check` returns a form verdict, `bin/waf-check` a request verdict; both print one JSON object
on STDOUT and send diagnostics to STDERR (`docs/INTEGRATION.md`, section 4):

```bash
php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64_JSON
php bin/waf-check  --config=/etc/spam.php \
  --json='{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
           "headers":{"host":"example.ru","content-type":"application/json"},
           "body":"{}","fields":{},"form":"lead"}'
```

| Bridge | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|---|---|---|---|---|
| `bin/spam-check` | clean | suspicious | spam | error |
| `bin/waf-check` | allow | — | block | error |

Exit codes: `docs/INTEGRATION.md`, section 4, and `docs/WAF.md`, CLI bridge. Note the 2.0 change in
`bin/spam-check`: the top-level shape and exit codes are unchanged, but `checks[].status` now uses
`spam|ham|uncertain|error` instead of `clean|suspicious|spam` (`docs/MIGRATION-1-to-2.md`, CLI output
change that matters).

A Node caller exists as `examples/node/bridge.mjs`; it wraps both bridges:

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

Rules for any bridge (`docs/INTEGRATION.md`, section 4): treat `status = error` and a missing answer
as fail open, process the form normally and log the error; keep the timeout short (two to five
seconds, the checker is local and CPU-bound); never mix diagnostics into STDOUT.

## 5. HTTP endpoint

`public/check.php` is a stateless POST JSON service protected by a shared key
(`docs/INTEGRATION.md`, section 5):

```bash
curl -s -X POST https://example.ru/check.php \
  -H 'Content-Type: application/json' \
  -H 'X-Spam-Checker-Key: ...' \
  -d '{"form":"contact","fields":{"email":"a@b.c"},"context":{"ip":"203.0.113.1","userAgent":"..."}}'
```

Response: `{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[...]}`; status codes
400 for invalid JSON, 403 for a wrong key, 405 for non-POST, 413 for a body over
`endpoint.max_body_bytes` (262144 bytes) and 500 for a checker error. The endpoint does not echo
submitted fields back and compares the key in constant time. The shared key is `endpoint.key`;
`SPAM_CHECKER_KEY` is the convention used by the shipped example, and the endpoint reads its
configuration path from `SPAM_CHECKER_CONFIG` (`docs/CONFIG.md`, Environment variables).

Keep the endpoint on an internal interface or localhost: it is safe there because it is
stateless, not because it authenticates the caller beyond the shared key (`docs/INTEGRATION.md`,
section 5).

## Testing an integration

Test the wiring before trusting it (`docs/INTEGRATION.md`, Testing an integration):

1. Unit-test the wiring with `storage.driver = memory`, `cache.driver = memory` and a stub context —
   no network, no filesystem.
2. Send a honeypot payload: expect spam and no e-mail sent.
3. Send a clean payload: expect clean and one normal lead.
4. Check the verdict log line for both.
5. In `shadow` mode verify that the application still processes spam payloads before switching to
   `enforce`.
6. For the WAF, run it in `monitor` for a day and compare the logged verdicts with the form verdicts
   before enabling `block`.

Run the shipped examples against a local or staging copy only — they use demo secrets and the system
temp directory (`docs/INTEGRATION.md`, same section).

## Next

- [Fail2Ban and Auto-Ban](06-Fail2Ban-And-AutoBan) — what the guard reports to the firewall.
- [Migration from 1.x](08-Migration-1-to-2) — the 1.x wiring keeps working; this page says what changed.
