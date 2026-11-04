# AGENTS.md — PHP Form Spam Checker

Operational contract for an agent that installs, wires or verifies this library
without a human in the loop. README prose is not a contract; this file is.

## Contents

- [What it is](#what-it-is) · [Download](#download) · [Install](#install) · [Verify](#verify-before-use) · [Use it non-interactively](#use-it-non-interactively)
- [Checks](#checks) · [Rules](#rules) · [Traps](#traps) · [Do not](#do-not) · [Layout](#layout) · [Report bugs](#report-bugs)

## What it is

Framework-agnostic spam filtering for PHP 8.5 forms plus an optional HTTP
firewall: a pipeline of 20 checks, a WAF with 9 rules, CLI/HTTP bridges and
structured evidence per verdict. No runtime Composer dependencies; a throwing
check or rule fails open.

## Download

```bash
composer require paulmann/php-form-spam-checker:2.1.2
git clone --depth 1 --branch v2.1.2 https://github.com/paulmann/PHP-Form-Spam-Checker.git
```

The first form is the fixed version; the clone adds tests, examples and docs.

## Install

Portable: copy the tree and `require autoload.php` from the application.
Persistent: `composer require` into the project; the runtime path needs no
Composer autoloader, because `autoload.php` works with and without `vendor/`.

## Verify before use

```bash
php -v                        # must print PHP 8.5 or newer
php bin/spam-check --help     # must print the option list and exit 0
php vendor/bin/phpunit        # after composer install; must be green
```

`bin/spam-check` exits `0` clean, `1` suspicious, `2` spam, `3` error;
`bin/waf-check` exits `0` allow, `2` block, `3` error. A changed exit code is a
contract change: stop and report instead of adapting silently.

## Use it non-interactively

| Rule | Why |
|---|---|
| No prompts: every bridge reads flags, `--stdin` or a base64 argument | the session is non-interactive |
| Secrets from `getenv()` only | a key on the command line is in the process list and shell history |
| Always pass `--config=` or `SPAM_CHECKER_CONFIG` | a missing config silently runs on defaults, and a missing secret disables behavioural checks |
| Read "empty" correctly | `uncertain` means "not checked" (network off or failed), not "clean" |

Minimal pipeline:

```bash
printf '%s' "$PAYLOAD" | php bin/spam-check --config=/etc/spam.php --form=contact --stdin --json
```

## Checks

| What | Command | Expectation |
|---|---|---|
| Syntax | `composer lint` | every file prints `No syntax errors detected` |
| Tests | `composer test:strict` | green under `failOnWarning`/`failOnRisky`/`failOnDeprecation` |
| Static analysis | `composer phpstan` | level `max`, zero errors |
| Taint analysis | `composer psalm` | zero errors |
| Style | `composer cs:check` | zero diffs |
| Coverage | `composer test:coverage`, then `php tools/coverage-gate.php .phpunit.cache/clover.xml --threshold=88 --threshold-methods=72 --exclude-env-adapters` | at or above the ratchet |
| Documents | `ghagent doc --root .` | exit `0` (github-agent 1.4.0: `python tools/ghagent.py`) |

A check that examined zero objects is a failure, not a pass.

## Rules

1. One logical change per commit, conventional imperative subject, motivation in the body.
2. Numbers are measured: name the command or the file behind every figure.
3. No secrets, tokens, keys or personal addresses in the tree, examples included.
4. `declare(strict_types=1);` in every PHP file; UTF-8 without BOM, LF line endings.
5. A new check implements `Check\SpamCheckInterface` and returns `Data\CheckOutcome`;
   a new rule implements `Waf\RuleInterface`. Register it, and add the key to `Config::defaults()`.
6. Update `CHANGELOG.md` under `[Unreleased]`; a new check or rule needs a positive
   fixture and a false-positive decoy.

## Traps

| Trap | Symptom | Action |
|---|---|---|
| PHP older than 8.5 | fatal on `readonly`/property hooks or a syntax error | check `php -v` first, do not patch the code down |
| Network checks on by default | tests become slow and flaky | they are off unless configured; keep them off in fixtures |
| WAF default mode | `block` expected, requests pass | default is `off`; enable it and start in `monitor` |
| Coverage drops below the ratchet | CI red on `tools/coverage-gate.php` | add fixtures; do not lower the threshold |

## Do not

- Add a runtime Composer dependency: the library loads from `autoload.php` and
  PHP extensions only.
- Enable `log.pii` or paste raw submissions into an issue; the verdict log is
  pseudonymised on purpose.
- Point `examples/` or a CLI probe at a production site or a real mailbox.
- Publish a release without green CI and release notes.

## Layout

```text
src/            library (Check/, Waf/, Pipeline/, Data/, Support/, adapters)
tests/          PHPUnit suite (unit + integration, no network)
bin/            CLI bridges: spam-check, waf-check, spam-train
config/         example and per-site configuration
integrations/   drop-in guard.php, waf.php, auto-prepend.php
public/         HTTP JSON endpoint (check.php)
docs/ examples/ long-form guides and runnable demos; qa-v2/ field QA evidence
```

## Report bugs

**https://github.com/paulmann/PHP-Form-Spam-Checker/issues/new/choose** — include
the version, PHP version, the exact command, the expected and actual verdict, and
the `evidence` block with secrets and personal data removed. Security
vulnerabilities go through `SECURITY.md`, never a public issue.
