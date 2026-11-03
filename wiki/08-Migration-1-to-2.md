# Migration from 1.x to 2.0 (and onward to 2.1)

2.0 keeps the public integration surface that deployed sites rely on and rebuilds the internals
around an ordered pipeline and explicit value objects. Most 1.x installations need **no code
change**; the breaking changes are limited to custom checks and to code that names the old internal
classes (`docs/MIGRATION-1-to-2.md`, introduction). 2.1 is additive on top of that surface: the
Fail2Ban bridge and the auto-ban are new, opt-in modules (`CHANGELOG.md`, `[2.1.0]`).

The contract source for the rewrite is `docs/ARCHITECTURE-V2.md`. If that document and this guide
disagree, the contract wins and the mismatch is worth reporting.

## Compatibility at a glance

| Surface | Status | What changed |
|---|---|---|
| `FormSpamChecker\SpamChecker` | kept | same constructor and `check()`, plus `checkRequest()`, `fromConfig()`, injected HTTP/cache/DNS |
| `FormSpamChecker\FormProtector` | kept | `fields()`, `verify()`, `verifyRequest()`; `fields()` renders more when configured |
| `FormSpamChecker\Integration\FormGuard` | kept | `boot()`, `run()`, `evaluateFor()` with the same signatures |
| `integrations/guard.php`, `integrations/auto-prepend.php` | kept | same files; the guard now runs the WAF first when enabled |
| `bin/spam-check` | kept | options, JSON output and exit codes unchanged; per-check `status` vocabulary changed |
| `public/check.php` | kept | same JSON service and `X-Spam-Checker-Key` |
| `config/sites/<host>.php` | kept | same format; `waf*` keys are optional |
| `FormSpamChecker\Status` | kept | `clean`, `suspicious`, `spam` |
| `FormSpamChecker\Config` | kept | array, dot access, `form()`; new sections are disabled by default |
| Custom checks | rewritten | `Check\SpamCheckInterface::check(RequestData): Data\CheckOutcome` |
| `FormSpamChecker\Verdict` | moved | now `FormSpamChecker\Data\Verdict` |
| `bin/waf-check`, `bin/spam-train` | added | new CLI bridges |
| `FormSpamChecker\Waf\*` | added | the firewall module |

Table: `docs/MIGRATION-1-to-2.md`, Compatibility at a glance.

## What moved or was renamed

| 1.x class (removed) | 2.0 replacement |
|---|---|
| `FormSpamChecker\CheckInterface` | `FormSpamChecker\Check\SpamCheckInterface` |
| `FormSpamChecker\CheckResult` | `FormSpamChecker\Data\CheckOutcome` |
| `FormSpamChecker\Submission` | `FormSpamChecker\Data\RequestData` |
| `FormSpamChecker\Verdict` | `FormSpamChecker\Data\Verdict` |
| `FormSpamChecker\Pipeline` | `FormSpamChecker\Pipeline\SpamPipeline` |
| `FormSpamChecker\Checks\HoneypotCheck` … `XssCheck` | `FormSpamChecker\Check\HoneypotCheck` … `XssCheck` (same names, new namespace) |

Quote: `docs/MIGRATION-1-to-2.md`, What moved or was renamed. Consequences for application code: a
type hint `FormSpamChecker\Verdict` becomes `FormSpamChecker\Data\Verdict`; code that only calls
`$verdict->isSpam()`, `$verdict->score`, `$verdict->reasons()` or `$verdict->status->value` keeps
working because the methods and the JSON shape are unchanged.

## Porting a custom check

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

2.0 — statuses are explicit and scores are capped at 100:

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
            return CheckOutcome::suspicious('my_check', 20, 'phone is required');
        }

        return CheckOutcome::ham('my_check');
    }
}
```

Both snippets and the mapping are `docs/MIGRATION-1-to-2.md`, Custom checks:

| 1.x | 2.0 |
|---|---|
| `clean` | `CheckStatus::HAM` with score 0 |
| `suspicious` | `CheckStatus::HAM` with a positive score (`CheckOutcome::suspicious()`) |
| `spam` | `CheckStatus::SPAM` (`CheckOutcome::spam()`) |
| — | `CheckStatus::UNCERTAIN` (no data, contributes 0) |
| — | `CheckStatus::ERROR` (check failed, fails open, contributes 0) |

Register an extra check by appending it to the default list:

```php
$checks = [...\FormSpamChecker\SpamChecker::defaultChecks($config, $storage), new MyCheck()];
$checker = new \FormSpamChecker\SpamChecker($config, $storage, $checks);
```

The pipeline catches anything a check throws and records `ERROR`, so a broken check never blocks a
form — unchanged from 1.x (`docs/MIGRATION-1-to-2.md`, Custom checks).

## The one output change that matters

The top-level shape of `bin/spam-check` is unchanged: `form`, `status`
(`clean|suspicious|spam`), `score`, `reasons` and the exit codes `0/1/2/3` are stable. What changed is
the per-check vocabulary in `checks[].status`: `clean|suspicious|spam` became
`ham|uncertain|error|spam`. A consumer that branched on `checks[].status === 'clean'` must branch on
`'ham'` or simply on the score; consumers that read only the top-level `status` need no change
(`docs/MIGRATION-1-to-2.md`, CLI output change that matters).

The two new bridges are `bin/waf-check` (exit `0` allow, `2` block, `3` error) and `bin/spam-train`
(exit `0` ok, `3` error) — `docs/MIGRATION-1-to-2.md`, New CLI bridges in 2.0.

## `FormProtector::fields()` renders more

`fields()` now emits, in order: the honeypot (dynamic HMAC-derived name when
`behavioral.honeypot.dynamic` is on and a secret of at least 16 characters exists, otherwise the
static `honeypot.fields` list), the signed time-trap token when `time_trap.enabled`, and the JS
challenge fields with the inline script when `behavioral.js_challenge.enabled`
(`docs/MIGRATION-1-to-2.md`, `FormProtector::fields()` changed).

Existing templates that call `<?= $protector->fields('contact') ?>` need no change. A custom
`honeypot.fields` list stops being used for rendering only when dynamic mode is active; set
`behavioral.honeypot.dynamic = false` to keep exactly the 1.x markup.

## Configuration additions are opt-in

Every new section is disabled by default, so upgrading does not change behaviour until you opt in;
unknown 1.x keys are preserved and ignored (`docs/MIGRATION-1-to-2.md`, Configuration additions):

| Section | Enable with |
|---|---|
| `pipeline` | `pipeline.stop_on_spam` (default `true`) |
| `http` | used by network checks: timeout, user agent |
| `cache` | `cache.driver` = `file` (default) / `memory` / `none` |
| `behavioral.honeypot` | `dynamic = true` plus a secret of at least 16 characters |
| `behavioral.js_challenge` | `enabled = true` plus a secret (or `time_trap.secret`) |
| `abuseipdb` | `enabled = true` plus `api_key`; threshold 90, 6 h cache, 429 back-off, circuit breaker |
| `dnsbl` | `enabled = true`; a hit is hard spam |
| `spf` / `dmarc` | `enabled = true`; score only |
| `bayes` | `enabled = true` plus a trained model |
| `waf` | `enabled = true`, `mode = monitor` or `block` |
| `autoban`, `fail2ban` (2.1) | `enabled = true`; see [Fail2Ban and Auto-Ban](06-Fail2Ban-And-AutoBan) |

The 2.1 rows are from `docs/CONFIG.md`, Fail2Ban and auto-ban (2.1); the rest are
`docs/MIGRATION-1-to-2.md`, Configuration additions.

Enabling everything at once turns a diagnostic problem into a mystery. Enable one module at a time,
keep `waf` last and in `monitor` first, and review `var/log/` for a day before switching the guard to
`enforce` (`docs/MIGRATION-1-to-2.md`, Checklist for an existing 1.x installation).

## WAF in the shared guard

`integrations/guard.php` runs the WAF layer **first** when `waf.enabled` is set in the site
configuration, then the form pipeline — no extra include is needed. `integrations/waf.php` remains
for sites without a form guard; do not load both. `integrations/auto-prepend.php` runs the WAF
independently of the legacy `auto` flag (`docs/MIGRATION-1-to-2.md`, WAF in the shared guard).

## Rollback

Every 2.0 and 2.1 module is additive and configuration-gated, so rollback is a configuration change
first (`docs/MIGRATION-1-to-2.md`, Rollback):

1. `waf.enabled = false` (or `waf_mode = off`) — the WAF include becomes a no-op;
2. `'mode' => 'shadow'` in `config/sites/<host>.php` — the form guard logs but never blocks;
3. set the new sections back to their defaults (`behavioral.honeypot.dynamic` false,
   `js_challenge.enabled` false, `abuseipdb`/`dnsbl`/`spf`/`dmarc`/`bayes`/`waf`/`autoban`/`fail2ban`
   enabled false) — the 1.x pipeline behaves exactly as before;
4. if you must return to the 1.x code, redeploy the 1.x checkout with
   `deploy/install-shared.sh`; keep `config/sites/`, because the 1.x loader ignores 2.0-only keys;
5. counters under `var/sites/` are disposable rate-limit state and may be deleted; verdict logs under
   `var/log/` are append-only JSONL and can be archived before switching versions.

A 1.x `public/check.php` caller and 1.x `bin/spam-check` callers keep working against a 2.x
deployment: the top-level verdict contract and exit codes are unchanged (only `checks[].status`
differs).

## Checklist for an existing 1.x installation

- [ ] confirm PHP 8.5 — `>=8.5`, the same requirement as 1.x, so nothing changes if the install
      already runs on 8.5;
- [ ] `composer install`, or copy `autoload.php` and `src/` for a plain install;
- [ ] run `php -l` on the configuration and `bin/spam-check` on a sample payload;
- [ ] search the code for the removed class names and update type hints and imports;
- [ ] port custom checks to `Check\SpamCheckInterface`;
- [ ] if the code parses `checks[].status`, update the vocabulary;
- [ ] enable new modules one at a time, the WAF last and in `monitor` first;
- [ ] review `var/log/` for a day before switching the guard to `enforce`.

Checklist: `docs/MIGRATION-1-to-2.md`, Checklist for an existing 1.x installation.

## Next

- [Checks](04-Checks) — the current check contract and pipeline order.
- [Configuration](03-Configuration) — every new section in its place.
- Back to [Home](Home).
