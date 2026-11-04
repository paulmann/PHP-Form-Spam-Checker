# Installation

The library is one PHP package with three entry points — a plain library, drop-in includes for a
shared server module, and CLI bridges — and no runtime dependency. "Installed" means the autoloader
resolves `FormSpamChecker\`, `php -v` reports PHP 8.5, and one probe returns a verdict.

## Requirements

| Requirement | Detail | Source |
|---|---|---|
| PHP 8.5 | `>=8.5`; CI runs 8.5.12 and 8.5 | `README.md`, Requirements |
| `ext-json`, `ext-mbstring` | always required | `composer.json`, `require` |
| `ext-curl` | only for the bundled HTTP client (AbuseIPDB) | `README.md`, Requirements |
| Runtime Composer dependencies | none | `README.md`, Requirements |
| Dev toolchain | PHP 8.5.12 and Composer 2 for the test suite | `CONTRIBUTING.md`, Requirements |

## Composer

```bash
composer require paulmann/php-form-spam-checker
```

To pin the release in an automated deployment:

```bash
composer require paulmann/php-form-spam-checker:2.1.2
```

Both commands are quoted from `AGENTS.md`, section Download; the package name is
`paulmann/php-form-spam-checker` in `composer.json`.

## Plain copy

Copy the repository somewhere PHP can read it and include the bundled autoloader:

```php
require '/var/www/lib/PHP-Form-Spam-Checker/autoload.php';
```

`autoload.php` works with and without `vendor/`, which is why a shared module needs no Composer
autoloader (`README.md`, Installation).

## What the tree contains

| Path | Purpose | Source |
|---|---|---|
| `src/` | the library (`Check/`, `Waf/`, `Pipeline/`, `Data/`, `Support/`, adapters) | `AGENTS.md`, Layout |
| `bin/spam-check` | form verdict for non-PHP callers; exit `0` clean, `1` suspicious, `2` spam, `3` error | `AGENTS.md`, Verify before use |
| `bin/waf-check` | WAF verdict for non-PHP callers; exit `0` allow, `2` block, `3` error | `docs/WAF.md`, CLI bridge |
| `bin/spam-train` | Bayesian model training and inspection | `docs/INTEGRATION.md`, Training the Bayesian model |
| `integrations/guard.php` | drop-in: WAF first (when enabled), then the form pipeline | `docs/INTEGRATION.md`, section 2 |
| `integrations/waf.php` | drop-in: firewall only | `docs/INTEGRATION.md`, section 3 |
| `integrations/auto-prepend.php` | pool-wide include; the WAF layer runs independently of the legacy `auto` flag | `docs/WAF.md`, Deployment |
| `public/check.php` | stateless POST JSON HTTP endpoint | `docs/INTEGRATION.md`, section 5 |
| `config/` | example configuration and per-site files | `docs/CONFIG.md`, Shared-guard site configuration |
| `examples/` | runnable demos, linted in CI | `README.md`, Testing |

## Verify before use

Run these three commands after installing (`AGENTS.md`, Verify before use):

```bash
php -v                        # must print PHP 8.5 or newer
php bin/spam-check --help     # must print the option list and exit 0
php vendor/bin/phpunit        # after composer install; must be green
```

The exit codes of the bridges are a contract, not a convenience: a changed code is a contract
change, so stop and report instead of adapting silently (`AGENTS.md`).

| Command | Exit 0 | Exit 1 | Exit 2 | Exit 3 |
|---|---|---|---|---|
| `bin/spam-check` | clean | suspicious | spam | error |
| `bin/waf-check` | allow | — | block | error |
| `bin/spam-train` | ok | — | — | error |

All four columns come from `AGENTS.md` (Verify before use), `docs/WAF.md` (CLI bridge) and
`docs/MIGRATION-1-to-2.md` (New CLI bridges in 2.0).

## Shared server module

For many sites on one server, install the module once and keep the code outside every document
root (`docs/INTEGRATION.md`, section 2):

```bash
deploy/install-shared.sh /path/to/checkout
deploy/init-site-state.sh example.ru www-example
```

`install-shared.sh` updates code only and never rewrites ownership under `var/`, so per-site state
keeps belonging to the site's PHP-FPM user (`CHANGELOG.md`, 2.0.0 Changed, and
`docs/MIGRATION-1-to-2.md`, Shared-module deployment). The script reads `PHP_BIN` (default
`/opt/php85/bin/php`) — see `docs/CONFIG.md`, Environment variables.

Wiring a site is one line in the form handler. Which include to pick is described in
[Integration](07-Integration).

## Upgrade an existing installation

1. Composer installs: `composer update` (or re-pin the new patch release).
2. Shared module: run `deploy/install-shared.sh` again with the new checkout; `config/sites/` is
   left in place.
3. No configuration change is required for an upgrade: every module added in 2.0 and the 2.1
   bridge are disabled by default (`docs/MIGRATION-1-to-2.md`, Configuration additions).

Rollback is a configuration change first — see [Migration from 1.x](08-Migration-1-to-2).

## Next

- [Quick Start](02-Quick-Start) — protect the first form.
- [Configuration](03-Configuration) — the keys you will actually change.
