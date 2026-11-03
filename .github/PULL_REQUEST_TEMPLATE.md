## What this changes

<!-- One paragraph: the defect or the capability, and why it matters. -->

## Type

- [ ] Fix — wrong behaviour in a check, a rule, a bridge or the documentation
- [ ] Feature — a new check, rule, adapter or CLI option
- [ ] Documentation — README, `docs/`, wiki, examples
- [ ] Chore — tooling, CI, dependencies

## Checklist

- [ ] `composer lint`, `composer test:strict`, `composer phpstan`, `composer psalm`, `composer cs:check` pass
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` (for behaviour changes)
- [ ] A new check or rule ships with a positive fixture and a false-positive decoy
- [ ] No secrets, tokens, keys, client IPs or personal data in the diff
- [ ] Text files are UTF-8 without BOM and LF; `declare(strict_types=1);` in new PHP files
- [ ] Documentation changed with the code when a flag, exit code or default changed

## Evidence

<!-- Commands you ran and their exit codes; a verdict/evidence block with values redacted. -->

Closes #
