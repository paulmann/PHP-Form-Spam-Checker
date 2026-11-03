# WAF — HTTP firewall guide

The 2.0 WAF inspects the **whole HTTP request** — method, URI, query string,
form fields, cookies, headers, raw body and (optionally) client-IP reputation —
before the application handles it. It is a library plus a drop-in include, not a
replacement for nginx/ModSecurity: it sees exactly what PHP sees, runs in the
same process as the application and answers with a plain HTTP response.

The WAF is **disabled by default** (`waf.enabled = false`). When enabled it
starts in `monitor` mode; switching to `block` is a deliberate, reviewed step.

## Contents

- [Threat model](#threat-model)
- [Architecture](#architecture)
- [Request lifecycle](#request-lifecycle)
- [Rules matrix](#rules-matrix)
- [Tuning a rule](#tuning-a-rule)
- [Monitor → block rollout](#monitor--block-rollout)
- [Deployment](#deployment)
- [Response behaviour](#response-behaviour)
- [Logging](#logging)
- [Performance](#performance)
- [CLI bridge for non-PHP back ends](#cli-bridge-for-non-php-back-ends)
- [Limits and non-goals](#limits-and-non-goals)

## Threat model

**Assets:** the PHP application behind the WAF, its data, and the integrity of
other visitors (stored XSS, header injection).

**Adversary:** a remote, unauthenticated client that sends arbitrary
request lines, headers, cookies and bodies. The adversary does not control the
server, the PHP process or the WAF configuration.

**Threats addressed:**

| Threat | Control |
|---|---|
| SQL injection probes (`' OR 1=1`, `UNION SELECT`, `SLEEP()`) | `sql_injection` rule |
| Cross-site scripting payloads (`<script>`, `javascript:`, event handlers) | `xss` rule |
| Path traversal / LFI probes (`../../etc/passwd`, `php://filter`) | `path_traversal` rule |
| OS command injection (`; curl …`, `$(id)`, `\| sh`) | `command_injection` rule |
| Vulnerability scanners and known admin/backdoor paths | `scanner` rule |
| Response splitting, log injection, request smuggling shapes | `header_injection` rule |
| Disallowed method, oversized body, surprising `Content-Type`, bad `Host` | `protocol` rule |
| Known-bad client IP (abuse reports, blocklists) | optional `ip_reputation` rule |
| Single-IP request floods | optional `rate_limit` rule |

**Assumptions and explicit non-goals:**

- The request has already been parsed by PHP: `$_SERVER`, `$_GET`, `$_POST`,
  `$_COOKIE` exist. The WAF runs inside PHP, so it cannot protect a static file
  served by nginx without PHP, nor block traffic at the TCP layer.
- PHP **folds repeated header lines** into one comma-separated `$_SERVER`
  value before user code runs. Original header framing (the classic
  request-smuggling signal) is therefore not observable; `header_injection`
  inspects the folded value instead.
- Uploaded file bytes are **not** pattern-scanned: a multipart body is treated as
  binary, so a JPEG containing `or 1=1` is not an attack. Scan file *metadata*
  at the application layer if needed.
- The WAF never rewrites or sanitises input. Prepared statements, output
  encoding and CSRF protection remain the application's responsibility.

## Architecture

| Class | Responsibility |
|---|---|
| `FormSpamChecker\Waf\Waf` | runs every rule over one request, aggregates findings |
| `FormSpamChecker\Waf\WafRequest` | immutable snapshot of the request (readonly) |
| `FormSpamChecker\Waf\WafFinding` | one finding: rule, severity 0–100, hard flag, reason, location, evidence |
| `FormSpamChecker\Waf\WafVerdict` | `blocked`, `status` (`clean`/`suspicious`/`blocked`), `score`, `findings`, `reasons()` |
| `FormSpamChecker\Waf\RuleInterface` | `name(): string`, `inspect(WafRequest): ?WafFinding` |
| `FormSpamChecker\Waf\AbstractRule` | enable switch, severity/hard overrides, pattern lists, text sources, allowlists |
| `FormSpamChecker\Integration\WafGuard` | modes, matching/skip, response, logging, fail-open |

The WAF itself is **mode-agnostic**: `Waf::inspect()` returns a verdict and has
no opinion about HTTP. `WafGuard` decides whether the verdict is only logged
(`monitor`) or answered (`block`). That split makes the same rules usable from a
library, a drop-in include and the CLI bridge.

```php
use FormSpamChecker\Config;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafRequest;

$config = Config::fromArray([
    'waf' => ['enabled' => true, 'mode' => 'monitor'],
]);

$request = WafRequest::fromGlobals($_SERVER, $_GET, $_POST, $_COOKIE);

$waf = Waf::withDefaultRules($config);
$verdict = $waf->inspect($request);

if ($verdict->isBlocked()) {
    // decide: 403, custom page, or log-only
}
```

`Waf::withDefaultRules()` accepts optional collaborators:

```php
Waf::withDefaultRules(
    $config,
    $ipReputationCheck,   // FormSpamChecker\Check\SpamCheckInterface|null
    $rateLimitStorage,    // FormSpamChecker\Storage\StorageInterface|null
    $logger,              // FormSpamChecker\Log\LoggerInterface|null
);
```

Without them the `ip_reputation` and `rate_limit` rules stay silent even when
enabled — the WAF never performs network or storage I/O it was not wired for.

## Request lifecycle

```text
request
  │
  ├─ WafGuard::run()
  │    ├─ WafRequest::fromGlobals()      body read from php://input, capped
  │    │    └─ error / exception ────────► allow (fail open), error_log
  │    ├─ shouldInspect()                enabled? mode != off? skip? match?
  │    │    └─ no ──────────────────────► allow
  │    ├─ Waf::inspect()
  │    │    ├─ sql_injection   ─┐
  │    │    ├─ xss             │  cheap content rules first,
  │    │    ├─ path_traversal  │  no network, no storage
  │    │    ├─ command_injection
  │    │    ├─ scanner          │
  │    │    ├─ header_injection │
  │    │    ├─ protocol         │
  │    │    ├─ ip_reputation   ─┤  optional: network / storage
  │    │    └─ rate_limit      ─┘
  │    │         └─ throwing rule ──────► skip rule, log, continue
  │    ├─ aggregate: hard finding OR sum(severity) >= waf.thresholds.block
  │    ├─ logVerdict()                    error_log when there are findings
  │    └─ mode == block && blocked?
  │         ├─ no ───────────────────────► allow
  │         └─ yes ──► reject(): HTTP status + X-WAF + body, exit
  │
  └─ application (only when the guard did not exit)
```

Aggregation rules:

1. any finding with `hard = true` → **blocked**;
2. otherwise `sum(severity)` capped at 100 `>= waf.thresholds.block` (default 60)
   → **blocked**;
3. `>= waf.thresholds.suspicious` (default 30) → **suspicious** (logged, not
   blocked);
4. otherwise **clean**.

A rule that throws is reported to the logger and skipped: one broken rule must
never turn the firewall into an outage.

## Rules matrix

All rules are enabled by default **except** `ip_reputation` and `rate_limit`.
A rule's configuration key is `waf.rules.<name>`.

| Rule | What it blocks | Severity | Hard | False-positive notes | Disable |
|---|---|---|---|---|---|
| `sql_injection` | high-precision SQLi signatures in URI, query, fields, cookies, text body (`UNION SELECT`, tautologies, `SLEEP(`, `information_schema`, comment-based probes) | 90 | yes | ordinary prose such as "select the report from the list" does not match; weaker heuristics were left to the form check | `'sql_injection' => false` |
| `xss` | `<script>`, event handlers, `javascript:`/`vbscript:`, `document.*` in request parameters | 90 | yes | entity-encoded variants (`&#60;script&#62;`) are not scanned here; they are the form check's job | `'xss' => false` |
| `path_traversal` | `../`/`..\` sequences anywhere scanned; file-probe signatures (`/etc/passwd`, `php://filter`) on the request line only | 85 | yes | a technician quoting `/etc/passwd` in a message field is fine; the probe patterns apply to the URI | `'path_traversal' => false` |
| `command_injection` | shell chaining into an executable, pipes into a shell, command substitution, `cat /etc/…`, Windows shell invocations | 90 | yes | requires shell syntax around the command; a semicolon in prose or a Markdown table row does not match | `'command_injection' => false` |
| `scanner` | paths only scanners ask for (`/.env`, `/.git`, `/wp-login.php`, `/phpmyadmin`, `/cgi-bin`, `/actuator`, …) and User-Agents naming attack tools (`sqlmap`, `nikto`, `nuclei`, `nmap`, …) | 80 | yes | a legitimate crawler with an odd UA is not matched unless it names a tool; extend `paths`/`user_agents` per site | `'scanner' => false` |
| `header_injection` | CR/LF/NUL inside a header value, invalid header names, a comma in `Host`, `Content-Length` or `Transfer-Encoding` | 80 | yes | folded list headers (`X-Forwarded-For`, `Accept-Language`) are excluded from the comma check | `'header_injection' => false` |
| `protocol` | disallowed method, negative/oversized body; score-only: surprising `Content-Type`, missing/invalid `Host` | 70 | method/body: yes; CT/Host: no | custom clients send unusual but harmless values — those findings are soft (CT 40, missing Host 25, invalid Host 50) | `'protocol' => false` |
| `ip_reputation` | client IP whose reputation check returns a hard spam verdict on or above the configured threshold | 100 | yes (when hard) | requires an injected `SpamCheckInterface` (e.g. `AbuseIpdbCheck`); disable if you do not want per-request network lookups | `'ip_reputation' => false` |
| `rate_limit` | more than `max` requests from one IP inside `window` seconds | 80 | yes | shared NAT (offices, mobile carriers) — keep the limit above real usage; requires `StorageInterface` | `'rate_limit' => false` |

Rule-specific options (all under `waf.rules.<name>`):

| Rule | Keys (defaults in brackets) |
|---|---|
| `protocol` | `methods` [`GET HEAD POST PUT PATCH DELETE OPTIONS`], `content_types` [`application/x-www-form-urlencoded`, `multipart/form-data`, `application/json`, `application/*+json`, `text/plain`], `max_body_bytes` [`waf.max_body_bytes`], `content_type_severity` [40], `content_type_hard` [false], `host_severity` [25 missing / 50 invalid], `host_hard` [false] |
| `scanner` | `paths`, `extra_paths`, `user_agents`, `extra_user_agents` |
| `rate_limit` | `max` [120], `window` [60 seconds] |
| `ip_reputation` | `threshold` [90] |
| content rules | `patterns`, `extra_patterns`, `allowlist`, `allow_patterns` |

## Tuning a rule

A rule value is either a boolean or an array. Arrays accept the shared keys
`enabled`, `severity`, `hard`, `patterns`, `extra_patterns`, `allowlist`,
`allow_patterns`:

```php
'waf' => [
    'enabled' => true,
    'mode' => 'block',
    'thresholds' => ['block' => 70, 'suspicious' => 40],
    'rules' => [
        // Off for this site.
        'command_injection' => false,

        // Softer, non-blocking scanner detection.
        'scanner' => ['severity' => 40, 'hard' => false],

        // Site-specific allowlist: a legacy endpoint really does use "..".
        'path_traversal' => [
            'allowlist' => ['#^/legacy/download\?#'],
        ],

        // Extra signature without forking the rule.
        'sql_injection' => [
            'extra_patterns' => ['/\bwaitfor\s+delay\b/i'],
        ],

        // Optional network-based rules.
        'ip_reputation' => ['enabled' => true, 'threshold' => 90],
        'rate_limit' => ['enabled' => true, 'max' => 240, 'window' => 60],
    ],
],
```

`allowlist` entries are PCRE patterns matched against the **text** being
scanned (for `scanner`: the path or the User-Agent).

## Monitor → block rollout

1. **Configure, keep it off.** Add the `waf` section to the site configuration
   and leave `'enabled' => false`. Nothing runs.
2. **Monitor.** `'enabled' => true, 'mode' => 'monitor'`. The verdict is
   computed and written through `error_log()`; the request always passes.
   Review for 1–3 days.
3. **Tune.** Disable a rule or make it soft (`'hard' => false`) where you see a
   false hit. Re-check the log — the WAF runs the same rules in every mode, so
   monitor-mode hits are exactly what block mode will block.
4. **Block.** `'mode' => 'block'`. Blocked requests get the configured status.
5. **Watch.** Keep the skip list covering admin and authenticated areas. A false
   positive in `block` mode takes the site's form down for that visitor.

Log lines to look for (see [Logging](#logging)):

```text
[waf] verdict example.ru POST /feedback.php from 203.0.113.10: mode=monitor status=blocked score=80 reasons=scanner: scanner User-Agent detected
```

## Deployment

### Drop-in for a PHP site

Copy the module to the shared location once (see
[docs/INTEGRATION.md](INTEGRATION.md)) and pick **one** include:

```php
// A site that uses the form guard: guard.php runs the WAF first (when
// waf.enabled is set), then the form pipeline. One include for both layers.
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';

// A site without a form guard (or a single front controller): the firewall
// alone, before the application handles the request.
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
```

Do not require both: the request would be inspected twice. Both drop-ins are
safe at the top of a front controller — they return without exiting when the
WAF is off, the mode is `monitor`, the request is skipped or the verdict is
clean. An exception inside either one degrades to "pass":

```php
// integrations/guard.php (simplified)
try {
    $waf = WafGuard::boot();
    if ($waf->enabled()) {
        $waf->run();
    }
} catch (\Throwable $exception) {
    error_log('[waf] bootstrap failed (fail open): ' . $exception->getMessage());
}

FormGuard::boot()->run();
```

`integrations/auto-prepend.php` runs the WAF layer independently of the legacy
`auto` flag: with `waf.enabled` set, every request of the pool is inspected,
while the form pipeline stays limited to matching endpoints.

### Site configuration

The same `config/sites/<host>.php` file the form guard reads:

```php
<?php
return [
    'site' => 'example.ru',

    // Optional top-level shortcuts (override the waf section below):
    'waf_mode'     => 'monitor',                 // off | monitor | block
    'waf_response' => 'auto',                    // auto | json | html | silent
    'waf_skip'     => ['#^/admin#i', '#^/login#i'],
    'waf_match'    => ['#^/api/#', '#^/feedback\.php#'],

    'config' => [
        'waf' => [
            'enabled' => true,
            'mode' => 'monitor',
            'block_status' => 403,
            'max_body_bytes' => 1048576,
            'rules' => [
                'ip_reputation' => false,
                'rate_limit' => false,
            ],
        ],
        'storage' => ['driver' => 'file', 'path' => '/var/www/lib/PHP-Form-Spam-Checker/var/sites/example.ru'],
    ],
];
```

Matching semantics:

- `waf_match` empty/absent → every request is inspected (except `waf_skip`);
- `waf_skip` protects administrative areas. If you set a non-empty list it
  **replaces** the built-in defaults; if it is empty or absent the built-in list
  is used:

  ```text
  #^/bitrix/admin#i   #^/wp-admin#i   #^/admin(?:/|$)#i
  #^/login(?:/|$)#i   #^/auth(?:/|$)#i   #^/cpanel(?:/|$)#i
  ```

- both `uri` and `path` are tested against each pattern.

### nginx / PHP-FPM

The WAF runs inside PHP, so it is installed through PHP, not through nginx
modules. Two equivalent options:

```nginx
# Option A: every PHP request of the site passes through the firewall.
# /etc/php/8.5/fpm/pool.d/example.conf
php_admin_value[auto_prepend_file] = /var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php
```

```php
// Option B: one line in the site's front controller (recommended when the
// site has a single entry point).
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
```

Option A also affects admin scripts and CLI-cron PHP; the skip list and
`waf.enabled` bound the cost, but review `waf_match` before enabling it for a
pool that serves heavy API traffic.

nginx still owns transport-level protections the WAF cannot provide:

```nginx
client_max_body_size 2m;
limit_req_zone $binary_remote_addr zone=forms:10m rate=5r/s;
limit_req zone=forms burst=20 nodelay;
```

`waf.max_body_bytes` caps the body the WAF reads from `php://input`; keep it
below or equal to `client_max_body_size`.

## Response behaviour

`WafGuard::reject()` answers and terminates:

| Setting | Behaviour |
|---|---|
| status (default) | `waf.block_status` (default `403`), header `X-WAF: blocked`, `Cache-Control: no-store` |
| `waf_response = 'json'` | `Content-Type: application/json`, body `{"ok":false,"error":"waf_blocked","message":"…"}` |
| `waf_response = 'html'` | `Content-Type: text/html`, minimal block page |
| `waf_response = 'silent'` | HTTP `200` with an empty body; the bot is not told it was blocked |
| `waf_response = 'auto'` (default) | JSON when `Accept: application/json` or the URI looks like `/api`, `/ajax`, `/json`; HTML otherwise |

`monitor` mode never changes the response: it computes and logs only.

Because the guard runs before the application, `http_response_code()` and
`header()` always work. If a site includes the WAF after output has started,
`headers_sent()` is respected and only the body is sent.

## Logging

The guard writes through `error_log()` (the `waf` channel); in `monitor` mode
this is the primary output:

```text
[waf] verdict <site> <METHOD> <uri> from <ip>: mode=<mode> status=<clean|suspicious|blocked> score=<0-100> reasons=<rule: reason; …>
[waf] blocked <site> <METHOD> <uri> from <ip>: mode=block score=<n> reasons=…
```

Ones without findings are not logged, so a healthy site stays quiet. Rule
failures and configuration problems are logged too:

```text
[waf] rule <name> failed, failing open: <message>
[waf] evaluation failed, failing open: <message>
[waf] cannot load config <path>: <message>
```

Evidence (`WafFinding::$evidence`) may contain a truncated match fragment; it
never contains the whole body or a whole field value.

## Performance

- Content rules are regular-expression scans over the URI, query values, form
  fields, cookies and a text body. They are the same in `monitor` and `block`
  mode, so monitor-mode timing is representative.
- The body is read once and truncated at `waf.max_body_bytes` (default 1 MiB).
  Multipart and binary bodies are skipped by content rules.
- No DNS, HTTP or storage I/O happens unless `ip_reputation` has an injected
  check or `rate_limit` has an injected storage.
- `rate_limit` costs one storage increment per inspected request; `ip_reputation`
  is bounded by `abuseipdb.cache_ttl` and the circuit breaker.
- On a normal form page the whole WAF pass is a few regex scans per request; it
  is not a per-byte scan of uploaded files.

## CLI bridge for non-PHP back ends

`bin/waf-check` runs the same rules out of process — useful for Node, Go or
Python servers that want every API request inspected before their own code sees
it:

```bash
php bin/waf-check --config=/var/www/lib/PHP-Form-Spam-Checker/config/sites/example.ru.php \
  --json='{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
           "headers":{"host":"example.ru","content-type":"application/json",
                      "user-agent":"Mozilla/5.0"},
           "cookies":{},"query":{},"body":"{\"email\":\"a@b.c\"}",
           "fields":{"email":"a@b.c"},"form":"lead"}'
```

Output (one JSON object on STDOUT):

```json
{"blocked":false,"status":"clean","score":0,"findings":[],"reasons":[]}
```

Exit codes: `0` allow, `2` block, `3` error (the error object has
`"status":"error"`). A disabled WAF answers `{"status":"disabled","blocked":false}`.

Important for non-browser callers: the `protocol` rule scores a missing
`Host` (25) and a missing `Content-Type` on a body-carrying method (40) as
**soft** findings. Together with the default block threshold of 60 that can
block a request that is not an attack. Always pass `host` and `content-type`
in the payload headers:

```json
{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
 "headers":{"host":"example.ru","content-type":"application/json"},
 "body":"…","fields":{…},"form":"lead"}
```

Input options: `--json=`, `--base64=`, `--stdin`, one positional base64
argument; `--config=` selects the configuration file (PHP array, JSON or a
shared-guard site config). STDOUT is JSON only; diagnostics go to STDERR.

Node sketch:

```js
import { execFile } from "node:child_process";

function inspect(request) {
  const payload = JSON.stringify(request);
  const base64 = Buffer.from(payload, "utf8").toString("base64");

  return new Promise((resolve) => {
    execFile("/usr/bin/php8.5", [
      "/var/www/lib/PHP-Form-Spam-Checker/bin/waf-check",
      "--config=/var/www/lib/PHP-Form-Spam-Checker/config/sites/example.ru.php",
      `--base64=${base64}`,
    ], { timeout: 2000 }, (error, stdout) => {
      // exit 2 also carries a valid JSON verdict on STDOUT
      try { resolve(JSON.parse(stdout)); }
      catch { resolve({ blocked: false, status: "error" }); }
    });
  });
}
```

Treat `status = "error"` (and a missing answer) as fail open.

## Limits and non-goals

- No response inspection (the WAF cannot hide a leaked secret from an
  application response).
- No TLS, throttling of connections, or protection for static files served
  without PHP.
- Repeated header lines are folded by PHP before the WAF runs; only the folded
  value is inspected.
- A determined attacker can encode a payload that a signature rule does not
  match. The WAF raises the cost of automated abuse; it does not prove an
  application safe.
- The WAF does not replace prepared statements, output encoding, CSRF tokens or
  authentication.

## See also

- [docs/INTEGRATION.md](INTEGRATION.md) — wiring the WAF next to the form guard
- [docs/CONFIG.md](CONFIG.md) — every `waf.*` key
- [docs/CHECKS.md](CHECKS.md#waf-rules-vs-form-checks) — WAF vs form check semantics
- [docs/MIGRATION-1-to-2.md](MIGRATION-1-to-2.md) — enabling the WAF on a 1.x install
