# Configuration

One `FormSpamChecker\Config` object is shared by the library, both guards, the CLI bridges and the
HTTP endpoint. It accepts a PHP array returned from a file, a JSON document, or an array passed to
`Config::fromArray()`. Every key is optional, the defaults are safe, and unknown keys are preserved
and ignored — which keeps configuration forward-compatible across upgrades (`docs/CONFIG.md`,
opening paragraph).

## Reading configuration in code

```php
$config = Config::fromFile(__DIR__ . '/config/spam-checker.php');

$config->int('rate_limit.max');        // 8
$config->bool('waf.enabled');          // false
$config->float('abuseipdb.threshold'); // 90.0
$config->string('behavioral.honeypot.secret');
$config->array('dnsbl.zones');
$config->get('forms.register');        // raw subtree

$register = $config->form('register'); // global tree + forms.register overrides
$config->toArray();                    // merged tree
```

The comments are the defaults documented in `docs/CONFIG.md`, section Accessing configuration in
code.

`Config::fromFile()` also accepts a **site configuration**: when the array has a `config` key
together with `site`, `mode`, `match` or `skip`, the inner `config` array is used. The CLI bridges,
the HTTP endpoint and both guards therefore read the same file (`docs/CONFIG.md`, same section).

## Keys worth knowing first

| Key | Default | Meaning | Source |
|---|---|---|---|
| `thresholds.spam` | `60` | capped score at which the verdict becomes spam | `docs/CONFIG.md`, Full default tree |
| `thresholds.suspicious` | `30` | capped score at which the verdict becomes suspicious | same |
| `pipeline.stop_on_spam` | `true` | stop on the first hard spam verdict, saving quota and DNS lookups | same |
| `rate_limit.max` / `window` | `8` / `900` s | requests per IP per window | same |
| `length.max` / `hard_max` | `5000` / `20000` | suspicious above `max`, hard spam above `hard_max` | same |
| `links.max` | `2` | links allowed in the whole message | same |
| `language.require_cyrillic` | `false` (reference deployments: `true`) | a configured name-like field must contain a Cyrillic letter; a Latin-only value adds `missing_score` (40 by default, 60 in the deployment configs) | same |
| `abuseipdb.threshold` | `90` | confidence score that becomes hard spam | same |
| `bayes.min_documents` | `20` | below this the model abstains | same |
| `waf.enabled` / `mode` | `false` / `monitor` | HTTP firewall switch and starting mode | same |
| `log.pii` | `false` | store the raw client IP and field samples | same |
| `storage.path` | system temp directory | counters, cache and model namespaces | same |

The complete default tree (every section and every comment) is `docs/CONFIG.md`, section Full
default tree; this page does not duplicate it.

## Supported but not materialised keys

Some keys are read by modules without appearing in `Config::defaults()`. Set them explicitly when
you need them (`docs/CONFIG.md`, Keys read by modules but absent from the default tree):

| Key | Read by | Default in code |
|---|---|---|
| `waf.response` | `WafGuard` | `auto` |
| `waf.thresholds.block` | `Waf` | 60 |
| `waf.thresholds.suspicious` | `Waf` | 30 |
| `waf.rules.<name>` as an array | `AbstractRule` | per-rule keys |
| `behavioral.honeypot.static` | `Honeypot` | falls back to `honeypot.fields` |
| `behavioral.js_challenge.max_age` | `JsChallenge` | 86400 |
| `bayes.hard` | `BayesCheck` | `false` |

## Per-form overrides

`forms.<id>` is merged on top of the global tree by `Config::form($id)`. The merge is recursive and
**lists replace** the global value instead of being appended (`docs/CONFIG.md`, Per-form overrides):

```php
'forms' => [
    'register' => [
        'rate_limit' => ['max' => 3, 'window' => 900],
        'links' => ['max' => 0],
        'behavioral' => ['js_challenge' => ['enabled' => true]],
    ],
    'contact' => [
        'time_trap' => ['enabled' => false],
        'abuseipdb' => ['threshold' => 95],
    ],
],
```

The form id is what `SpamChecker::check()`, `FormProtector::verify()`, `FormGuard` (`'form'` in the
site configuration) and the CLI (`--form=`) receive. Network checks honour per-form overrides too,
so one busy API form can raise `abuseipdb.threshold` or disable `dnsbl` without touching the rest.

## Environment variables

| Variable | Used by | Source |
|---|---|---|
| `SPAM_CHECKER_CONFIG` | default config path for `bin/spam-check`, `bin/waf-check`, `bin/spam-train` and `public/check.php` | `docs/CONFIG.md` |
| `SPAM_CHECKER_SECRET` | convention for `time_trap.secret` / `behavioral.*.secret` | same |
| `SPAM_CHECKER_KEY` | convention for `endpoint.key` | same |
| `ABUSEIPDB_KEY` | convention for `abuseipdb.api_key` | same |
| `PHP_BIN` | `deploy/install-shared.sh` (default `/opt/php85/bin/php`) | same |
| `SPAM_PHP`, `SPAM_CONFIG` | `examples/node/bridge.mjs` | same |

`.env` files are not loaded by the library: export the variables in the PHP-FPM pool
(`env[ABUSEIPDB_KEY] = …`) or read them in your own bootstrap (`docs/CONFIG.md`). Never commit a
key or secret — the shipped example configuration shows the `getenv()` pattern (`SECURITY.md`,
Secrets and keys).

## Storage, cache and logs

| Path | Derived from | Contains |
|---|---|---|
| counters | `storage.path` | rate-limit counters, `waf/` subdirectory in the shared guard |
| cache | `cache.path` (default `storage.path/cache`) | AbuseIPDB answers, circuit-breaker state, DNS answers, Bayesian model document |
| Bayesian model | `bayes.storage_path` | namespace for the model; the model itself lives in the cache |
| verdict log | `log.path` | append-only JSONL |
| per-site state | `var/sites/<site>/` | counters and, in the guard, `var/log/<site>.jsonl` |

The table follows `docs/CONFIG.md`, Storage and cache paths. Cache drivers are `file` (default),
`memory`/`array` and `none`/`null`; storage drivers are `file` (flock-protected JSON files) and
`memory` (`docs/CONFIG.md`).

Treat `storage.path` as internal data — the cache holds derived network answers keyed by client
IP — and keep it outside the document root with `0770`/`0775` and a group that only the web user
belongs to (`SECURITY.md`, Storage, cache and logs).

## Logging

`log.enabled` plus `log.path` appends one JSON line per checked submission. By default the client
IP is stored as a stable 16-hex pseudonym and field values are redacted; `log.pii = true` stores
the raw IP and truncated field samples, and `log.sample_fields = false` keeps only the pseudonymised
IP even in PII mode (`docs/CONFIG.md`, Logging; `SECURITY.md`, Storage, cache and logs).

```json
{"ts":"2026-11-03T12:00:00Z","form":"contact","status":"spam","score":100,
 "reasons":["honeypot: honeypot field filled: website"],"ip":"a1b2c3d4e5f6a7b8",
 "page":"/contacts/","checks":[{"check":"honeypot","status":"spam","score":100,
 "reason":"honeypot field filled: website","evidence":{"field":"website"}}],
 "fields":"redacted"}
```

This line is quoted from `docs/CONFIG.md`, Logging. The WAF writes its own verdict lines through
`error_log()`; `FormGuard` writes `var/log/<host>.jsonl` when no explicit `log` section is
configured (`docs/CONFIG.md`, Logging).

## Field exclusions

These field names are never treated as user content: `website`, `_fs_hp`, `_fs_ts`, `consent`,
`promo`, `tariff`, `device`, `devices`, `users`, `term`, `model`, `serial`, `verification`,
`verificationUntil`. Add project-specific names with `fields.exclude`; dynamic honeypot names and
JS challenge fields are excluded automatically (`docs/CONFIG.md`, Field exclusions).

## 2.1 keys: auto-ban and Fail2Ban

The 2.1 release adds two sections, both disabled by default: `autoban.*` (application-level IP ban)
and `fail2ban.*` (writing the `PHPFSC BAN` lines). Their keys, defaults and behaviour are described
in [Fail2Ban and Auto-Ban](06-Fail2Ban-And-AutoBan); the full table is `docs/CONFIG.md`, section
Fail2Ban and auto-ban (2.1).

## Next

- [Checks](04-Checks) — what each key actually changes.
- [WAF](05-WAF) — the `waf.*` subtree in practice.
