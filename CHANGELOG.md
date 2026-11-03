# Changelog

All notable changes to this project are documented here. The format is
[Keep a Changelog](https://keepachangelog.com/en/2.0.0/) 2.0.0, and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.2] - 2026-11-04

### Added

- **Cyrillic requirement for names** (`language.require_cyrillic`): configured
  name-like fields (`name`, `fio`, `first_name`, `last_name`, `surname`, …,
  case/separator-insensitive) must contain at least one Cyrillic letter. Fields
  with letters but no Cyrillic add `language.missing_score` points (reference
  deployments: 60 → hard spam); e-mail, company and free-text fields are never
  checked. `language.fields`, `min_letters` and `max_score` tune the rule.
- Reference deployment configs enable the rule on all sites; set
  `missing_score = 40` to downgrade it to "suspicious" instead of blocking.

## [2.1.0] - 2026-11-03

### Added

- **Application-level auto-ban** (`autoban`): after N hard-spam events inside a
  time window the client IP is banned in shared storage for a TTL; the new
  `autoban` pipeline check rejects it before any other check runs. Fail-open,
  configurable per site (`enabled`, `threshold`, `window`, `ttl`).
- **Fail2Ban bridge** (`FormSpamChecker\Security\Fail2Ban`): every hard-spam
  verdict (form pipeline) and every hard WAF block appends a single sanitized
  line `PHPFSC BAN ip=… site=… form=… score=… reason=…` to a configured log
  file, ready for a Fail2Ban filter/jail. `emit_on` selects `spam`, `waf` or
  `both`; `min_score` filters low-confidence events.
- Deployment guidance: Fail2Ban filter/jail, firewall ban limited to
  http/https, `ignoreip` for admin hosts, plus AbuseIPDB `threshold = 100`
  guidance (deployments use 100; library default stays 90).

### Security

- Fail2Ban log lines are LF-only, fields are token-sanitized (no whitespace or
  newline injection) and appended with `LOCK_EX`; reporting errors never change
  a verdict. Lines start with an ISO-8601 timestamp so the jail needs no
  "match without timestamp" fallback (the filter and jail are in
  [docs/WAF.md#fail2ban](docs/WAF.md#fail2ban)).
- `CurlClient` no longer calls the deprecated `curl_close()` (PHP 8.5).

## [2.0.0] - 2026-11-03

The 2.0 line rebuilds the internals around an ordered pipeline and explicit
value objects, and adds four new layers: a behavioural honeypot/JS challenge, IP
reputation and DNS blocklists, mail-domain authentication, a Bayesian
classifier, and an HTTP firewall. Every new module is **disabled by default**;
existing 1.x integrations keep working (see *Backward compatibility* under
Changed).

### Added

- **Ordered pipeline** — `FormSpamChecker\Pipeline\SpamPipeline` with early exit
  on the first hard spam (`pipeline.stop_on_spam`) and fail-open handling of
  throwing checks.
- **Value objects** — `Data\RequestData`, `Data\CheckOutcome`, `Data\CheckStatus`
  (`spam|ham|uncertain|error`), `Data\Verdict`.
- **PSR-shaped abstractions with bundled adapters** — `Http` (Curl client,
  PSR-18 adapter), `Cache` (file/array/null, PSR-16/PSR-6 adapters), `Log`
  (PSR-3-shaped interface, error-log/null/PSR-3 adapters), `Dns` (resolver
  interface, `dns_get_record` implementation, cached resolver).
- **Behavioural layer** — dynamic honeypot with hourly HMAC-derived field names
  (`DynamicHoneypotCheck`, `Behavioral\Honeypot`), JS challenge with a signed
  token and a self-contained inline script (`JsChallengeCheck`,
  `Behavioral\JsChallenge`, CSP-hash friendly).
- **IP reputation** — `Check\AbuseIpdbCheck`: AbuseIPDB v2 `check` endpoint,
  per-IP cache (6 h default), `threshold` (90), `maxAgeInDays`, `429`
  back-off from `Retry-After`/`X-RateLimit-Reset`, circuit breaker
  (`failures` 3 / `cooldown` 300 s), `fail_open`, no network for private or
  invalid addresses.
- **DNS blocklists** — `Check\DnsblCheck`: IPv4 and IPv6 (nibble) reversal,
  multiple zones, `127.0.0.0/24` listing detection, hard spam on a hit.
- **Mail-domain authentication** — `Check\SpfCheck` and `Check\DmarcCheck`
  (`Support\SpfEvaluator`, `Support\EmailAddress`); domain-level trust signals
  that only contribute a score, never a hard verdict.
- **Bayesian classifier** — `Bayes\Classifier`, `Bayes\UnicodeTokenizer`
  (lower-cased Unicode words + bigrams), `Bayes\Model`,
  `Bayes\CacheModelStorage`; multinomial naive Bayes with Laplace smoothing,
  probability clamped to `[0.01, 0.99]`, abstains below `min_documents`.
  Trained through `bin/spam-train` (`--ham`, `--spam`, `--text-ham`,
  `--text-spam`, `--stats`, `--reset`).
- **WAF** — `Waf\Waf`, `Waf\WafRequest`, `Waf\WafVerdict`, `Waf\WafFinding`,
  `Waf\RuleInterface`, `Waf\AbstractRule` and nine rules: `sql_injection`,
  `xss`, `path_traversal`, `command_injection`, `scanner`, `header_injection`,
  `protocol`, optional `ip_reputation`, optional `rate_limit`. Modes
  `off|monitor|block`, default skip list for admin areas, JSON/HTML/silent
  responses, fail-open.
- **WAF drop-in** — `integrations/waf.php` + `Integration\WafGuard` for PHP
  sites (same per-site config file as the form guard, optional top-level
  `waf_mode`, `waf_skip`, `waf_match`, `waf_response`).
- **WAF CLI bridge** — `bin/waf-check` (`--json`, `--base64`, `--stdin`,
  `--config`); exit codes `0` allow, `2` block, `3` error.
- **Form verdict CLI bridge** — `bin/spam-check` (1.x contract; per-check
  statuses now use the 2.0 vocabulary).
- **Quality gates in CI** — PHP CS Fixer (PSR-12/PER-CS2), PHPStan `level: max`
  with strict rules and bleeding edge, Psalm taint analysis, PHPUnit with
  `failOnWarning`/`failOnRisky`/`failOnDeprecation`, coverage gate on line and
  method coverage (`tools/coverage-gate.php`), `php -l` over `src`, `tests`,
  `bin`, `integrations`, `config`, `public`, `examples`, `tools`.
- **Configuration sections** — `pipeline`, `http`, `cache`, `abuseipdb`,
  `dnsbl`, `spf`, `dmarc`, `dkim` (reserved), `bayes`, `behavioral`, `waf`.
  All disabled by default; unknown keys are preserved.
- **Documentation** — `README.md` / `README.ru.md` rewritten for 2.0,
  `docs/WAF.md`, `docs/MIGRATION-1-to-2.md`, updated `docs/CONFIG.md`,
  `docs/CHECKS.md`, `docs/INTEGRATION.md`, `docs/INTEGRATION.ru.md`,
  `SECURITY.md`, and new examples (`examples/waf.php`,
  `examples/abuseipdb.php`, `examples/bayes-train.php`).
- **Examples** — `examples/plain-form.php` uses the 2.0 configuration;
  `examples/node/bridge.mjs` documents both the form and the WAF bridge.

### Changed

- The default pipeline builds checks through
  `SpamChecker::defaultChecks($config, $storage, …)`; network and behavioural
  checks are registered only when enabled and only after the local checks.
- `SpamChecker` accepts optional `LoggerInterface`, `HttpClientInterface`,
  `CacheInterface` and `ResolverInterface` collaborators (constructor and
  `fromConfig()`); a `RequestData` can be passed to `checkRequest()`.
- `FormProtector::fields()` now renders the dynamic honeypot and the JS
  challenge when they are configured; static honeypot rendering is unchanged.
- `FormGuard` keeps the 1.x `off|shadow|enforce` modes and `config/sites`
  format; it additionally understands the `auto` flag at the top level.
- Verdict logging stores richer evidence and uses the 2.0 check names.
- Deployment scripts update code only and never rewrite ownership under
  `var/` (multi-user hosts); per-site state is initialised by
  `deploy/init-site-state.sh`.
- Dependencies are unchanged in the runtime path (`ext-json`, `ext-mbstring`;
  `ext-curl` is needed only for the bundled HTTP client), and PHP 8.5 remains
  the requirement (`>=8.5`, as in 1.x).
- `FormSpamChecker\Verdict` moved to `FormSpamChecker\Data\Verdict`;
  `FormSpamChecker\Pipeline` moved to `FormSpamChecker\Pipeline\SpamPipeline`.
  Type hints and imports must be updated.
- `bin/spam-check` per-check `checks[].status` changed from
  `clean|suspicious|spam` to `spam|ham|uncertain|error`. The top-level status
  and exit codes are unchanged.
- A check's "suspicious" result is expressed as `HAM` **with a positive score**
  instead of a separate status.
- The WAF identifies scanners by explicit path and User-Agent markers; it does
  not score User-Agent entropy (deliberately: entropy is not a reliable signal).
- **Backward compatibility (kept; no code changes required):**
  - `FormSpamChecker\SpamChecker` — constructor, `check(array $fields,
    ?Context, string $formId): Verdict`.
  - `FormSpamChecker\FormProtector` — `fields()`, `verify()`, `verifyRequest()`.
  - `FormSpamChecker\Integration\FormGuard` — `boot()`, `run()`, `evaluateFor()`.
  - `bin/spam-check` — options, top-level JSON output and exit codes `0/1/2/3`.
  - `public/check.php` — POST JSON service, `endpoint.key` /
    `X-Spam-Checker-Key`, status codes 400/403/405/413/500.
  - `config/sites/<host>.php` — the 1.x shared-guard format, including
    `site`, `mode`, `form`, `response`, `match`, `skip`, `auto`, `config`.
  - `FormSpamChecker\Status` — `clean`, `suspicious`, `spam`.
  - `FormSpamChecker\Config` — array/JSON/PHP-file loading, dot access, deep
    merge, per-form overrides.

### Deprecated

- `dkim` check: the `dkim` configuration section is accepted and reserved, but
  no `FormSpamChecker\Check\DkimCheck` ships in 2.0.0 and the pipeline does not
  register one.
- `behavioral.js_challenge.min_ms`: accepted in configuration and documented as
  reserved, not enforced yet (the token age is checked through `max_age`).

### Removed

- `FormSpamChecker\CheckInterface`, `CheckResult`, `Submission` and the
  `FormSpamChecker\Checks\*` classes are removed. Custom checks implement
  `FormSpamChecker\Check\SpamCheckInterface` and receive
  `Data\RequestData`, returning `Data\CheckOutcome` (see
  `docs/MIGRATION-1-to-2.md`).

[Unreleased]: https://github.com/paulmann/PHP-Form-Spam-Checker/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/paulmann/PHP-Form-Spam-Checker/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/paulmann/PHP-Form-Spam-Checker/commits/v2.0.0
