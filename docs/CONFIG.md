# Configuration reference

`FormSpamChecker\Config` accepts a PHP array (returned from a file), a JSON
document or an array passed to `Config::fromArray()`. Every key is optional; the
defaults below are the values used by the standard pipeline. Unknown keys are
preserved and ignored, which keeps configuration forward-compatible across
upgrades.

## Contents

- [Accessing configuration in code](#accessing-configuration-in-code)
- [Full default tree](#full-default-tree)
- [Keys read by modules but absent from the default tree](#keys-read-by-modules-but-absent-from-the-default-tree)
- [Per-form overrides](#per-form-overrides)
- [Environment variables](#environment-variables)
- [Storage and cache paths](#storage-and-cache-paths)
- [Field exclusions](#field-exclusions)
- [Logging](#logging)
- [Shared-guard site configuration](#shared-guard-site-configuration)

## Accessing configuration in code

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

`Config::fromFile()` also accepts a **shared-guard site configuration**: when
the array has a `config` key together with `site`, `mode`, `match` or `skip`,
that inner `config` array is used. The CLI bridges, the HTTP endpoint and both
guards therefore read the same file.

## Full default tree

```php
[
    // ---------------------------------------------------------------- verdict
    'thresholds' => [
        'suspicious' => 30,    // capped score sum at which the verdict is "suspicious"
        'spam' => 60,          // ... and "spam"; any hard SPAM check wins regardless
    ],

    // ------------------------------------------------------------------ input
    'fields' => [
        'max_length' => 5000,  // kept for compatibility; see length.max
        'exclude' => [],       // extra field names never inspected as user content
    ],

    // ------------------------------------------------------------ behavioural
    'honeypot' => [            // 1.x keys, still used for static honeypot mode
        'enabled' => true,
        'fields' => ['website', '_fs_hp'],
        'score' => 100,
    ],
    'time_trap' => [
        'enabled' => false,          // opt-in: requires a rendered secret
        'field' => '_fs_ts',
        'secret' => '',              // >= 16 chars, required when enabled
        'min_seconds' => 2,
        'max_seconds' => 604800,     // 7 days: cached pages remain usable
        'require_token' => true,
        'suspicious_score' => 30,    // missing / expired token
        'spam_score' => 80,          // forged token / too fast
    ],
    'behavioral' => [
        'honeypot' => [
            'dynamic' => true,       // HMAC-derived field name, rotates hourly
            'field_prefix' => '_hp_',
            'secret' => '',          // >= 16 chars; falls back to time_trap.secret
            'missing_score' => 10,   // dynamic mode: neither field posted
            // 'static' => [],       // optional: override the static list
        ],
        'js_challenge' => [
            'enabled' => false,
            'field' => '_js',        // token lives in "<field>_token"
            'secret' => '',          // >= 16 chars; falls back to time_trap.secret
            'missing_score' => 15,   // never a hard SPAM
            'min_ms' => 0,           // reserved
            'max_age' => 86400,      // token lifetime
        ],
    ],

    // ---------------------------------------------------------------- content
    'user_agent' => [
        'enabled' => true,
        'allow_empty' => false,
        'extra_blocklist' => [],
        'empty_score' => 40,
        'blocked_score' => 100,
    ],
    'rate_limit' => [
        'enabled' => true,
        'max' => 8,
        'window' => 900,             // seconds
        'per_form' => true,
        'score' => 100,
    ],
    'keywords' => [
        'enabled' => true,
        'words' => [/* RU + EN starter list */],
        'patterns' => [],            // raw PCRE, applied to the normalised text
        'per_hit' => 12,
        'max_score' => 90,
        'scan_fields' => [],         // empty = all non-excluded fields
    ],
    'links' => [
        'enabled' => true,
        'max' => 2,
        'score_per_extra' => 15,
        'shortener_score' => 35,
        'shorteners' => [/* bit.ly, tinyurl.com, ... */],
        'obfuscated_score' => 25,
    ],
    'sql_injection' => [
        'enabled' => true,
        'spam_score' => 100,
        'suspicious_score' => 40,
    ],
    'xss' => [
        'enabled' => true,
        'spam_score' => 100,
        'suspicious_score' => 45,
    ],
    'email' => [
        'enabled' => true,
        'fields' => ['email', 'personalEmail', 'e-mail', 'mail'],
        'invalid_score' => 40,
        'disposable_score' => 70,
        'disposable_domains' => [],  // extra domains, suffix match
    ],
    'length' => [
        'enabled' => true,
        'max' => 5000,
        'score' => 30,
        'hard_max' => 20000,
        'hard_score' => 100,
    ],
    'repetition' => [
        'enabled' => true,
        'min_run' => 12,
        'min_word_repeats' => 4,
        'score' => 25,
        'max_score' => 60,
    ],
    'language' => [
        'enabled' => false,
        'mixed_script_score' => 20,
        'max_score' => 40,
    ],

    // --------------------------------------------------------------- pipeline
    'pipeline' => [
        'stop_on_spam' => true,      // first hard SPAM stops the run (saves quota)
    ],

    // --------------------------------------------------- network / reputation
    'http' => [
        'timeout' => 2.0,
        'user_agent' => 'PHP-Form-Spam-Checker/2.0',
    ],
    'cache' => [
        'driver' => 'file',          // file | memory (a.k.a. array) | none (a.k.a. null)
        'path' => '',                // default: storage.path + /cache
    ],
    'abuseipdb' => [
        'enabled' => false,
        'api_key' => '',             // read from the environment in your config
        'threshold' => 90,           // abuseConfidenceScore at which it is hard spam
        'cache_ttl' => 21600,        // 6 h
        'timeout' => 2.0,
        'max_age_days' => 30,        // AbuseIPDB maxAgeInDays
        'fail_open' => true,         // true: lookup failure = UNCERTAIN; false: ERROR
        'circuit_breaker' => [
            'failures' => 3,         // consecutive transport/5xx failures
            'cooldown' => 300,       // seconds the breaker stays open
        ],
    ],
    'dnsbl' => [
        'enabled' => false,
        'zones' => ['zen.spamhaus.org', 'bl.spamcop.net'],
        'cache_ttl' => 3600,
        'timeout' => 2,
        'hit_score' => 100,          // listing = hard SPAM with this score
    ],
    'spf' => [
        'enabled' => false,
        'fields' => ['email', 'personalEmail'],
        'missing_score' => 10,       // no usable SPF policy
        'lookup_limit' => 10,        // RFC 7208 DNS lookup budget
        'dns_ttl' => 3600,
    ],
    'dmarc' => [
        'enabled' => false,
        'fields' => ['email', 'personalEmail'],
        'missing_score' => 10,       // no/!invalid DMARC record
        'weak_policy_score' => 5,    // p=none
        'dns_ttl' => 3600,
    ],
    'dkim' => [
        'enabled' => false,          // planned in this release: no checker yet
        'required' => false,
    ],

    // ---------------------------------------------------------------- bayesian
    'bayes' => [
        'enabled' => false,
        'storage_path' => '',        // default: storage.path + /bayes
        'threshold' => 0.92,         // spam probability that scores
        'min_documents' => 20,       // below this the model abstains
        'score_scale' => 100,        // score = round(probability * scale)
        // 'hard' => false,          // true: a match is a hard SPAM (default false)
    ],

    // --------------------------------------------------------------------- waf
    'waf' => [
        'enabled' => false,
        'mode' => 'monitor',         // off | monitor | block
        'block_status' => 403,
        'max_body_bytes' => 1048576, // body read cap (php://input)
        // 'response' => 'auto',      // auto | json | html | silent
        // 'thresholds' => ['block' => 60, 'suspicious' => 30],
        'rules' => [
            'sql_injection' => true,
            'xss' => true,
            'path_traversal' => true,
            'command_injection' => true,
            'scanner' => true,
            'header_injection' => true,
            'protocol' => true,
            'ip_reputation' => false,   // needs an injected reputation check
            'rate_limit' => false,      // needs injected storage
        ],
    ],

    // ----------------------------------------------------------------- output
    'log' => [
        'enabled' => false,
        'path' => '',
        'pii' => false,
        'sample_fields' => true,
    ],
    'storage' => [
        'driver' => 'file',          // file | memory
        'path' => '',                // default: sys_get_temp_dir()/php-form-spam-checker
    ],
    'endpoint' => [
        'key' => '',                 // shared key for the HTTP bridge
        'max_body_bytes' => 262144,
    ],

    // --------------------------------------------------------------- per form
    'forms' => [
        // 'register' => ['rate_limit' => ['max' => 3]],
    ],
]
```

## Keys read by modules but absent from the default tree

These are supported without being materialised by `Config::defaults()`; set
them explicitly when you need them:

| Key | Read by | Default in code |
|---|---|---|
| `waf.response` | `WafGuard` | `auto` |
| `waf.thresholds.block` | `Waf` | 60 |
| `waf.thresholds.suspicious` | `Waf` | 30 |
| `waf.rules.<name>` as an array | `AbstractRule` | per-rule (`enabled`, `severity`, `hard`, `patterns`, `extra_patterns`, `allowlist`, …) |
| `behavioral.honeypot.static` | `Honeypot` | fallback to `honeypot.fields` |
| `behavioral.js_challenge.max_age` | `JsChallenge` | 86400 |
| `bayes.hard` | `BayesCheck` | `false` |

## Per-form overrides

`forms.<id>` is merged on top of the global tree by `Config::form($id)`. The
merge is recursive; **lists replace** the global value instead of being
appended, so a form that redefines `links.shorteners` gets exactly its list.

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

The form id is passed to `SpamChecker::check()`, `FormProtector::verify()`,
`FormGuard` (`'form' => 'contact'` in the site config) and the CLI
(`--form=register`). Network checks honour per-form overrides too, so a busy
API form can raise `abuseipdb.threshold` or disable `dnsbl` without touching the
rest.

## Environment variables

| Variable | Where it is used |
|---|---|
| `SPAM_CHECKER_CONFIG` | default config path for `bin/spam-check`, `bin/waf-check`, `bin/spam-train` and `CheckEndpoint::fromEnvironment()` (i.e. `public/check.php`) |
| `SPAM_CHECKER_SECRET` | convention used by the shipped example config for `time_trap.secret` / `behavioral.*.secret` |
| `SPAM_CHECKER_KEY` | convention used by the shipped example config for `endpoint.key` |
| `ABUSEIPDB_KEY` | convention used by `examples/abuseipdb.php` for `abuseipdb.api_key` |
| `PHP_BIN` | `deploy/install-shared.sh` (default `/opt/php85/bin/php`) |
| `SPAM_PHP`, `SPAM_CONFIG` | `examples/node/bridge.mjs` |

`.env` files are not loaded by the library: export the variables in the
PHP-FPM pool (`env[ABUSEIPDB_KEY] = …`) or read them in your own bootstrap
before constructing `Config`.

## Storage and cache paths

| Path | Derived from | Contains |
|---|---|---|
| counters | `storage.path` (default `sys_get_temp_dir()/php-form-spam-checker`) | rate-limit counters, WAF rate-limit counters (`waf/` subdirectory in the shared guard) |
| cache | `cache.path` (default `storage.path/cache`) | AbuseIPDB responses, circuit-breaker state, DNS answers, Bayesian model document |
| Bayesian model | `bayes.storage_path` (default `storage.path/bayes`) | namespace for the model; the model itself is stored in the cache |
| verdict log | `log.path` | append-only JSONL |
| per-site state (shared guard) | `var/sites/<site>/` | counters and, in the guard, `var/log/<site>.jsonl` |

Cache drivers: `file` (default, works on shared hosting), `memory`/`array`
(per-process, tests), `none`/`null` (disables caching — every network lookup
goes out). Storage drivers: `file` (flock-protected JSON files) and `memory`.

## Field exclusions

These fields are never treated as user content (honeypot, tokens, technical
selects): `website`, `_fs_hp`, `_fs_ts`, `consent`, `promo`, `tariff`, `device`,
`devices`, `users`, `term`, `model`, `serial`, `verification`,
`verificationUntil`. Add project-specific names with `fields.exclude`.

Dynamic honeypot names (`_hp_<hash>`) and JS challenge fields (`_js`,
`_js_token`) are excluded automatically by the checks that need it; the
`BayesCheck` also strips them from the classified text.

## Logging

`log.enabled` + `log.path` appends one JSON line per checked submission. By
default the IP is stored as a stable 16-hex pseudonym and the fields are
redacted. Set `log.pii` to store the raw IP and truncated field samples
(`log.sample_fields = false` keeps only the pseudonymised IP even in PII mode).

```json
{"ts":"2026-11-03T12:00:00Z","form":"contact","status":"spam","score":100,
 "reasons":["honeypot: honeypot field filled: website"],"ip":"a1b2c3d4e5f6a7b8",
 "page":"/contacts/","checks":[{"check":"honeypot","status":"spam","score":100,
 "reason":"honeypot field filled: website","evidence":{"field":"website"}}],
 "fields":"redacted"}
```

The WAF writes its own verdict lines through `error_log()`; see
[docs/WAF.md](WAF.md#logging). `FormGuard` writes `var/log/<host>.jsonl`
by default when no explicit `log` section is configured.

## Shared-guard site configuration

A site config wraps the pipeline configuration and adds guard metadata. It is
accepted by `Config::fromFile()`, both guards and the CLI bridges:

```php
<?php
return [
    'site' => 'example.ru',
    'mode' => 'shadow',              // off | shadow | enforce
    'form' => 'contact',
    'response' => 'auto',            // auto | json | html | silent
    'auto' => false,                 // only for integrations/auto-prepend.php

    'match' => ['#^/feedback\.php#'],
    'skip'  => ['#^/admin#', '#^/login#'],

    // Optional WAF shortcuts (same file):
    'waf_mode'     => 'monitor',     // off | monitor | block
    'waf_skip'     => ['#^/admin#i'],// replaces the built-in skip list
    'waf_match'    => ['#^/api/#'],
    'waf_response' => 'auto',

    'config' => [
        'thresholds' => ['spam' => 60],
        'rate_limit' => ['max' => 8, 'window' => 900],
        'waf' => ['enabled' => true, 'mode' => 'monitor'],
    ],
];
```

The guard defaults storage and logging into the module's `var/` tree unless the
site config sets them explicitly (see `FormGuard::boot()`).
