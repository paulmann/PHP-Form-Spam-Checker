# Configuration reference

`FormSpamChecker\Config` accepts an array (PHP file or JSON). Every key is
optional; the defaults below are the values used by the standard pipeline.
Unknown keys are preserved and ignored, which keeps configuration
forward-compatible across upgrades.

## Accessing configuration in code

```php
$config = Config::fromFile(__DIR__ . '/config/spam-checker.php');
$config->int('rate_limit.max');       // 8
$config->bool('honeypot.enabled');    // true
$config->form('register');            // global config + forms.register overrides
```

## Full default tree

```php
[
    'thresholds' => [
        'suspicious' => 30,    // capped score sum at which the verdict is "suspicious"
        'spam' => 60,          // ... and "spam"; any hard Spam check wins regardless
    ],
    'fields' => [
        'max_length' => 5000,  // kept for compatibility; see length.max
        'exclude' => [],       // extra field names never inspected as user content
    ],
    'honeypot' => [
        'enabled' => true,
        'fields' => ['website', '_fs_hp'],
        'score' => 100,
    ],
    'time_trap' => [
        'enabled' => false,          // opt-in because it requires a rendered secret
        'field' => '_fs_ts',
        'secret' => '',              // >= 16 chars, required when enabled
        'min_seconds' => 2,
        'max_seconds' => 604800,     // 7 days: cached pages remain usable
        'require_token' => true,
        'suspicious_score' => 30,    // missing / expired token
        'spam_score' => 80,          // forged token / submitted too fast
    ],
    'user_agent' => [
        'enabled' => true,
        'allow_empty' => false,
        'extra_blocklist' => [],
        'empty_score' => 40,         // suspicious
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
    'log' => [
        'enabled' => false,
        'path' => '',
        'pii' => false,
        'sample_fields' => true,
    ],
    'storage' => [
        'driver' => 'file',          // 'file' or 'memory'
        'path' => '',                // default: sys_get_temp_dir()/php-form-spam-checker
    ],
    'endpoint' => [
        'key' => '',                 // shared key for the HTTP bridge
        'max_body_bytes' => 262144,
    ],
    'forms' => [
        // 'register' => ['rate_limit' => ['max' => 3]],
    ],
]
```

## Per-form overrides

`forms.<id>` is merged on top of the global tree by `Config::form($id)`. Lists
replace the global value instead of being appended, so a form that redefines
`honeypot.fields` gets exactly its list.

```php
'forms' => [
    'register' => [
        'rate_limit' => ['max' => 3, 'window' => 900],
        'links' => ['max' => 0],
    ],
    'contact' => [
        'time_trap' => ['enabled' => false],
    ],
],
```

## Field exclusions

These fields are never treated as user content (honeypot, token, technical
selects): `website`, `_fs_hp`, `_fs_ts`, `consent`, `promo`, `tariff`, `device`,
`devices`, `users`, `term`, `model`, `serial`, `verification`,
`verificationUntil`. Add project-specific names with `fields.exclude`.

## Storage

File storage is the default because it works on shared hosting. It writes one
small JSON file per key under `storage.path`, uses `flock` for atomic
increments, and occasionally garbage-collects expired entries. For very high
traffic, implement `FormSpamChecker\Storage\StorageInterface` over Redis and
pass it to the `SpamChecker` constructor.

## Logging

`log.enabled` + `log.path` appends one JSON line per checked submission. By
default the IP is stored as a stable 16-hex pseudonym and the fields are
redacted. Set `log.pii` to store the raw IP and truncated field samples.

```json
{"ts":"2026-11-03T12:00:00Z","form":"contact","status":"spam","score":100,
 "reasons":["honeypot: honeypot field filled: website"],"ip":"a1b2c3d4e5f6a7b8",
 "page":"/contacts/","checks":[{...}],"fields":"redacted"}
```
