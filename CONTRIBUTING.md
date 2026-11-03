# Contributing

Thanks for improving PHP Form Spam Checker.

## Requirements

- PHP 8.5.12
- Composer 2

## Workflow

```bash
composer install
composer test          # PHPUnit
composer lint          # php -l
```

All tests must stay green, including the strict gates in `phpunit.xml`:

- `failOnWarning`, `failOnRisky`, `failOnDeprecation`;
- `beStrictAboutOutputDuringTests`.

## Adding a check

1. Create `src/Checks/YourCheck.php` implementing `FormSpamChecker\CheckInterface`.
2. Return `CheckResult::clean|suspicious|spam` — hard Spam only for evidence
   that cannot occur in a legitimate message.
3. Add defaults to `Config::defaults()` under your check's key.
4. Register the check in `SpamChecker::defaultChecks()`.
5. Add unit tests for positive, negative, disabled and custom-config cases.
6. Document semantics and false-positive guidance in `docs/CHECKS.md`.

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
