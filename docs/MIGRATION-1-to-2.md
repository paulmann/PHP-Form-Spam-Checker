# Migration guide: 1.x → 2.0

2.0 keeps the public integration surface that deployed sites rely on and
rebuilds the internals around an ordered pipeline and explicit value objects.
Most 1.x installations need **no code change** — only the new modules are
opt-in. The breaking changes are limited to custom checks and to code that
names the old internal classes.

> Contract source: [docs/ARCHITECTURE-V2.md](ARCHITECTURE-V2.md). If this guide
> and the contract disagree, the contract wins — report the mismatch.

## Compatibility at a glance

| Surface | 1.x | 2.0 | Status |
|---|---|---|---|
| `FormSpamChecker\SpamChecker` | constructor + `check()` | same, plus `checkRequest()`, `fromConfig()`, injected HTTP/cache/DNS | ✅ kept |
| `FormSpamChecker\FormProtector` | `fields()`, `verify()`, `verifyRequest()` | same; `fields()` also renders the JS challenge and the dynamic honeypot when configured | ✅ kept |
| `FormSpamChecker\Integration\FormGuard` | `boot()`, `run()`, `evaluateFor()` | same signatures | ✅ kept |
| Shared module | `integrations/guard.php`, `integrations/auto-prepend.php` | same files | ✅ kept |
| `bin/spam-check` | options, JSON output, exit codes `0/1/2/3` | same contract; per-check `status` values changed (see below) | ✅ kept |
| `public/check.php` | JSON service, `X-Spam-Checker-Key` | same | ✅ kept |
| `config/sites/<host>.php` | plain array with `site`/`mode`/`config` | same; new `waf*` keys are optional | ✅ kept |
| `FormSpamChecker\Status` | `clean`/`suspicious`/`spam` | same enum and values | ✅ kept |
| `FormSpamChecker\Config` | array, dot access, `form()` | same, new sections disabled by default | ✅ kept |
| Custom checks | `CheckInterface::check(Submission): CheckResult` | `Check\SpamCheckInterface::check(RequestData): Data\CheckOutcome` | ❌ rewritten |
| `FormSpamChecker\Verdict` | final value object | now `FormSpamChecker\Data\Verdict` | ⚠️ moved |
| `bin/waf-check`, `bin/spam-train` | — | new CLI bridges | ➕ added |
| `FormSpamChecker\Waf\*` | — | new WAF module | ➕ added |

## What moved / was renamed

| 1.x class (removed) | 2.0 replacement |
|---|---|
| `FormSpamChecker\CheckInterface` | `FormSpamChecker\Check\SpamCheckInterface` |
| `FormSpamChecker\CheckResult` | `FormSpamChecker\Data\CheckOutcome` |
| `FormSpamChecker\Submission` | `FormSpamChecker\Data\RequestData` |
| `FormSpamChecker\Verdict` | `FormSpamChecker\Data\Verdict` |
| `FormSpamChecker\Pipeline` | `FormSpamChecker\Pipeline\SpamPipeline` |
| `FormSpamChecker\Checks\HoneypotCheck` … `XssCheck` (12 classes) | `FormSpamChecker\Check\HoneypotCheck` … `XssCheck` (same names, new namespace) |
| `Status` case `Clean`/`Suspicious`/`Spam` | unchanged (same class, same cases) |

Consequences for application code:

- a type hint such as `function handle(FormSpamChecker\Verdict $v)` must become
  `FormSpamChecker\Data\Verdict`;
- code that only calls `$verdict->isSpam()`, `->score`, `->reasons()`,
  `->status->value` keeps working — the methods and JSON shape are unchanged;
- a custom check must be ported (see [Custom checks](#custom-checks)).

## Custom checks

1.x:

```php
use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Submission;

final class MyCheck implements CheckInterface
{
    public function name(): string { return 'my_check'; }

    public function check(Submission $submission): CheckResult
    {
        return $submission->value('phone') === ''
            ? CheckResult::suspicious('my_check', 20, 'phone is required')
            : CheckResult::clean('my_check');
    }
}
```

2.0 (statuses are explicit; scores are capped at 100):

```php
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

final readonly class MyCheck implements SpamCheckInterface
{
    public function name(): string { return 'my_check'; }

    public function check(RequestData $data): CheckOutcome
    {
        if ($data->field('phone') === '') {
            // HAM with a positive score = "suspicious"
            return CheckOutcome::suspicious('my_check', 20, 'phone is required');
        }

        return CheckOutcome::ham('my_check');
    }
}
```

Status mapping:

| 1.x | 2.0 |
|---|---|
| `clean` | `CheckStatus::HAM` + score 0 |
| `suspicious` | `CheckStatus::HAM` + positive score (`CheckOutcome::suspicious()`) |
| `spam` | `CheckStatus::SPAM` (`CheckOutcome::spam()`) |
| — | `CheckStatus::UNCERTAIN` (no data, contributes 0) |
| — | `CheckStatus::ERROR` (check failed, fails open, contributes 0) |

Registering an extra check:

```php
$checks = [...\FormSpamChecker\SpamChecker::defaultChecks($config, $storage), new MyCheck()];
$checker = new \FormSpamChecker\SpamChecker($config, $storage, $checks);
```

The pipeline catches anything a check throws and records `ERROR` — a broken
check never blocks a form (unchanged from 1.x).

## CLI output change that matters

The top-level shape of `bin/spam-check` is unchanged:

```json
{"form":"contact","status":"clean","score":0,"reasons":[],"checks":[…]}
```

`form`, `status` (`clean|suspicious|spam`), `score`, `reasons` and the exit
codes `0/1/2/3` are stable. What changed is the **per-check status vocabulary**:

| Field | 1.x | 2.0 |
|---|---|---|
| `checks[].status` | `clean` / `suspicious` / `spam` | `ham` / `uncertain` / `error` / `spam` |
| `checks[].score` | 0–100 | 0–100 (unchanged) |
| `checks[].reason`, `checks[].evidence` | present | present (evidence is richer) |

A consumer that branched on `checks[].status === 'clean'` must branch on
`'ham'` (or simply on the score). Consumers that only read the top-level
`status` need no change.

New CLI bridges in 2.0 (not a BC concern, just available):

- `bin/waf-check` — WAF verdict for non-PHP back ends; exit codes `0` allow,
  `2` block, `3` error;
- `bin/spam-train` — Bayesian model training and inspection; exit codes `0`
  ok, `3` error. (The Lead's earlier wording mentioned `bin/spam-check train`;
  the shipped entry point is the separate `bin/spam-train`.)

## `FormProtector::fields()` changed

`fields()` now emits, in this order:

1. the honeypot — dynamic HMAC-derived name when
   `behavioral.honeypot.dynamic` is on **and** `behavioral.honeypot.secret`
   (or the shared `time_trap.secret`) is at least 16 characters; otherwise the
   static list `honeypot.fields` (1.x behaviour);
2. the signed time-trap token when `time_trap.enabled`;
3. the JS challenge fields and inline script when
   `behavioral.js_challenge.enabled`.

Existing templates that call `<?= $protector->fields('contact') ?>` need no
change. A custom `honeypot.fields` list stops being used for rendering only
when dynamic mode is active; to keep exactly 1.x markup, set
`behavioral.honeypot.dynamic = false`.

## Configuration additions

All new sections are **disabled by default**, so upgrading does not change
behaviour until you opt in. Unknown keys from 1.x configs are preserved and
ignored.

| Section | Enable with | Notes |
|---|---|---|
| `pipeline` | `pipeline.stop_on_spam` (default `true`) | early exit on the first hard spam |
| `http` | used by network checks | timeout, user agent |
| `cache` | `cache.driver` = `file` (default) / `memory` / `none` | file cache under `storage.path/cache` |
| `behavioral.honeypot` | `dynamic = true` + a ≥16-char `secret` | dynamic field names; `missing_score` 10 |
| `behavioral.js_challenge` | `enabled = true` + a ≥16-char `secret` (or `time_trap.secret`) | suspicion only, never hard spam |
| `abuseipdb` | `enabled = true` + `api_key` | threshold 90, 6 h cache, 429 back-off, circuit breaker |
| `dnsbl` | `enabled = true` | `zen.spamhaus.org`, `bl.spamcop.net`; a hit is hard spam |
| `spf` / `dmarc` | `enabled = true` | domain-level trust signals, score only |
| `bayes` | `enabled = true` + trained model | train with `bin/spam-train` |
| `waf` | `enabled = true`, `mode = monitor` \| `block` | see [docs/WAF.md](WAF.md) |

Full reference: [docs/CONFIG.md](CONFIG.md).

## Enabling each module

```php
// 1. Behavioural: dynamic honeypot + JS challenge.
'behavioral' => [
    'honeypot' => ['dynamic' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
    'js_challenge' => ['enabled' => true, 'secret' => getenv('SPAM_CHECKER_SECRET') ?: ''],
],

// 2. IP reputation (needs a key; fail-open by default).
'abuseipdb' => ['enabled' => true, 'api_key' => getenv('ABUSEIPDB_KEY') ?: ''],

// 3. DNS blocklists.
'dnsbl' => ['enabled' => true],

// 4. Mail-domain authentication (score only).
'spf' => ['enabled' => true],
'dmarc' => ['enabled' => true],

// 5. Bayesian classifier.
'bayes' => ['enabled' => true, 'threshold' => 0.92, 'min_documents' => 20],

// 6. HTTP firewall (start in monitor).
'waf' => ['enabled' => true, 'mode' => 'monitor'],
```

The Bayesian model must be trained before `bayes` contributes:

```bash
php bin/spam-train --config=/etc/spam.php --ham=/etc/spam/ham.txt --spam=/etc/spam/spam.txt
php bin/spam-train --config=/etc/spam.php --stats
```

### WAF in the shared guard

`integrations/guard.php` now runs the WAF layer **first** when `waf.enabled` is
set in the site config, then the form pipeline — no extra include is needed:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
```

`integrations/waf.php` remains available for sites without a form guard (it
runs the firewall alone). Do not load both: the request would be inspected
twice. `integrations/auto-prepend.php` runs the WAF independently of the legacy
`auto` flag, so a pool can be firewalled while the form pipeline stays limited
to its form endpoints.

## Environment variables

| Variable | Used by |
|---|---|
| `SPAM_CHECKER_CONFIG` | `bin/spam-check`, `bin/waf-check`, `bin/spam-train`, `public/check.php` |
| `SPAM_CHECKER_SECRET` | your config file for `time_trap.secret` / `behavioral.*.secret` |
| `SPAM_CHECKER_KEY` | your config file for `endpoint.key` |
| `ABUSEIPDB_KEY` | your config file for `abuseipdb.api_key` |
| `PHP_BIN` | `deploy/install-shared.sh` (default `/opt/php85/bin/php`) |
| `SPAM_PHP`, `SPAM_CONFIG` | `examples/node/bridge.mjs` |

Never commit an API key or a secret: read them from the environment in the
config file (the shipped `config/spam-checker.example.php` shows the pattern).

## Shared-module deployment (unchanged)

```bash
deploy/install-shared.sh /path/to/checkout
deploy/init-site-state.sh example.ru www-example
```

`install-shared.sh` updates code only and never rewrites ownership under
`var/`; per-site counters/logs stay owned by the site's PHP-FPM user.
`docs/INTEGRATION.md` repeats the full rollout.

## Rollback

Every 2.0 module is additive and configuration-gated, so rollback is a config
change first:

1. `waf.enabled = false` (or `waf_mode = off`) — the WAF include becomes a
   no-op;
2. `'mode' => 'shadow'` in `config/sites/<host>.php` — the form guard logs but
   never blocks;
3. set the new sections back to their defaults (`behavioral.honeypot.dynamic`
   false, `js_challenge.enabled` false, `abuseipdb/dnsbl/spf/dmarc/bayes/waf`
   enabled false). The 1.x pipeline behaves exactly as before;
4. if you must return to the 1.x code, redeploy the 1.x checkout with
   `deploy/install-shared.sh`. Keep `config/sites/` — the 1.x loader ignores
   2.0-only keys (unknown keys are preserved and ignored);
5. counters under `var/sites/` are disposable rate-limit state and can be
   deleted; verdict logs under `var/log/` are append-only JSONL and can be
   archived before switching versions.

A 1.x `public/check.php` and `bin/spam-check` callers keep working against a
2.0 deployment: the top-level verdict contract and exit codes are unchanged
(only `checks[].status` vocabulary differs, see above).

## Checklist for an existing 1.x installation

- [ ] confirm PHP 8.5 (`>=8.5`, same requirement as 1.x; CI runs 8.5.12 and
      8.5) — nothing to change if the 1.x install already runs on 8.5;
- [ ] `composer install` (or copy `autoload.php` + `src/` for a plain install);
- [ ] run `php -l` on your config, and `bin/spam-check` on a sample payload;
- [ ] grep your code for the removed class names (table above) and update type
      hints / imports;
- [ ] port custom checks to `Check\SpamCheckInterface`;
- [ ] if you parse `checks[].status`, update the vocabulary;
- [ ] enable new modules one at a time, WAF last and in `monitor` first;
- [ ] review `var/log/` for a day before switching the guard to `enforce`.
