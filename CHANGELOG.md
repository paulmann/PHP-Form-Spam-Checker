# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Framework-agnostic `SpamChecker` with 12 local checks: honeypot, signed time
  trap, user-agent, durable rate limit, length/control characters, SQL
  injection, XSS, links/shorteners/obfuscation, keywords, e-mail quality
  (syntax + disposable domains), repetition, mixed-script homoglyphs.
- `Config` with dot-notation access, deep merge, per-form overrides and PHP/JSON
  file loading.
- `FormProtector` helper that renders honeypot + HMAC time-trap fields and
  verifies the current POST request.
- `Token\FormToken`: HMAC-SHA-256 signed, URL-safe, form-bound tokens.
- `Storage\FileStorage` (flock, atomic counters, TTL, garbage collection) and
  `Storage\MemoryStorage` for tests.
- `Log\VerdictLogger`: JSONL verdict log, IP pseudonymisation and field
  redaction by default, optional PII mode.
- CLI bridge `bin/spam-check` (inline JSON, base64 argument or STDIN; exit codes
  0/1/2/3) and HTTP bridge `public/check.php` with optional shared key.
- Shared-server integration: `integrations/guard.php` and
  `integrations/auto-prepend.php`, per-site configs with `off` / `shadow` /
  `enforce` modes.
- 177 PHPUnit tests (453 assertions) covering every check, pipeline
  aggregation, storage, token, logging, CLI and the HTTP endpoint, plus a
  syntax gate for every PHP file.
- CI on PHP 8.5.12 and 8.5 with strict warning/risky/deprecation gates.
- Documentation (EN/RU), integration guide, configuration and check reference,
  plain-PHP and Node examples, shared-module install script.

[Unreleased]: https://github.com/Paulmann/PHP-Form-Spam-Checker/commits/main
