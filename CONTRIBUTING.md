# Contributing

Thanks for improving PHP Form Spam Checker.

## Requirements

- PHP 8.5 or newer (CI runs `8.5.12` and `8.5`)
- Composer 2

## Workflow

```bash
composer install
composer qa            # CS Fixer, PHPStan max, Psalm taint, strict PHPUnit
composer lint          # php -l
composer test:coverage # coverage gate: 88 % lines / 72 % methods
```

All tests must stay green, including the strict gates in `phpunit.xml`:

- `failOnWarning`, `failOnRisky`, `failOnDeprecation`;
- `beStrictAboutOutputDuringTests`.

## Adding a check

1. Create `src/Check/YourCheck.php` implementing
   `FormSpamChecker\Check\SpamCheckInterface`; `check()` receives a
   `Data\RequestData` and returns a `Data\CheckOutcome`.
2. Return `CheckStatus::SPAM|HAM|UNCERTAIN|ERROR` — hard `SPAM` only for evidence
   that cannot occur in a legitimate message.
3. Add defaults to `Config::defaults()` under your check's key.
4. Register the check in `SpamChecker::defaultChecks()`.
5. Add unit tests for positive, negative, disabled and custom-config cases, plus a
   false-positive decoy.
6. Document semantics and false-positive guidance in `docs/CHECKS.md`.
7. Add an entry under `[Unreleased]` in `CHANGELOG.md`.

## Adding a WAF rule

1. Create `src/Waf/Rules/YourRule.php` extending `Waf\AbstractRule` (or
   implementing `Waf\RuleInterface`).
2. Return findings with the rule id, location and a short evidence fragment —
   never the whole request body or a whole field value.
3. Keep it fail-open: a rule that throws must not block a request.
4. Add a positive fixture and a decoy in `tests/Unit/Waf/Rules/` and enable the
   rule in the example configuration.
5. Document it in the rules matrix in `docs/WAF.md`.

## Style

- `declare(strict_types=1);` in every file.
- PSR-12 layout, 4 spaces, final classes by default, readonly properties.
- No runtime dependencies.
- Comments explain *why*, not *what*; public methods have docblocks with types.

## Commits and PRs

- One logical change per PR.
- Describe the false-positive/negative trade-off when changing thresholds or
  patterns.
- Update `CHANGELOG.md` under `[Unreleased]`.

## Licence

By contributing you agree that your work is released under the MIT licence.
