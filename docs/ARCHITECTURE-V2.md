# PHP Form Spam Checker 2.0 — architecture contract

This document is the shared contract for the 2.0 rewrite. Every module in 2.0 is
built against it; keep signatures and semantics stable once a module is merged.

## Goals

1. **Ordered pipeline** with early exit on hard spam.
2. **Layered protection cycle**: behavioural signals → local content heuristics →
   network reputation (AbuseIPDB, DNSBL) → mail-domain authentication
   (SPF/DMARC/DKIM) → Bayesian classifier.
3. **WAF** for the whole HTTP request (query, body, cookies, headers, method,
   size, IP reputation), usable both as a library and as a drop-in
   `auto_prepend_file`.
4. **PSR-shaped abstractions** for HTTP, cache and logging, with included
   adapters and no mandatory runtime dependency.
5. **PHP 8.5 features** used where they improve the design: `readonly final`
   value objects, property hooks, asymmetric visibility (`public private(set)`),
   the `|>` pipe operator and `#[\NoDiscard]`.
6. **Quality gates**: PSR-12/PER-CS via PHP CS Fixer, PHPStan `level: max` with
   strict rules and bleeding edge, Psalm with taint analysis, PHPUnit with code
   coverage, CI blocking merges.

## Namespaces

| Namespace | Responsibility |
|---|---|
| `FormSpamChecker\Data` | immutable request/check/verdict value objects |
| `FormSpamChecker\Check` | `SpamCheckInterface` implementations (one responsibility each) |
| `FormSpamChecker\Pipeline` | ordered execution, early exit, aggregation |
| `FormSpamChecker\Behavioral` | dynamic honeypot, JS challenge, time trap helpers |
| `FormSpamChecker\Waf` | request firewall, rules, verdict |
| `FormSpamChecker\Http` | HTTP client abstraction and adapters |
| `FormSpamChecker\Cache` | cache abstraction and adapters |
| `FormSpamChecker\Log` | PSR-3-shaped logger abstraction and adapters |
| `FormSpamChecker\Dns` | DNS resolver abstraction and cached resolver |
| `FormSpamChecker\Bayes` | Bayesian classifier and model storage |
| `FormSpamChecker\Support` | patterns, IP/text helpers |
| `FormSpamChecker\Integration` | `FormGuard` (forms) and `WafGuard` (HTTP) drop-ins |
| `FormSpamChecker\Storage` | existing key/counter storage (rate limiting) |

Backward-compatibility facades kept for already-deployed integrations:
`FormSpamChecker\SpamChecker`, `FormSpamChecker\FormProtector`,
`FormSpamChecker\Integration\FormGuard`, `bin/spam-check`, `public/check.php`,
`config/sites/<host>.php`.

## Core value objects

```php
final readonly class RequestData
{
    /**
     * @param array<string, mixed>  $fields
     * @param array<string, string> $headers
     * @param array<string, string> $cookies
     * @param array<string, mixed>  $query
     */
    public function __construct(
        public array $fields = [],
        public string $ip = '',
        public array $headers = [],
        public array $cookies = [],
        public array $query = [],
        public string $method = 'POST',
        public string $uri = '',
        public string $body = '',
        public ?int $now = null,
        public string $formId = 'default',
    ) {}

    public function field(string $name): string;
    public function hasField(string $name): bool;
    /** @return array<string, string> */
    public function content(array $exclude = []): array;
    public function text(array $exclude = []): string;
    public function header(string $name): string;   // case-insensitive
    public function userAgent(): string;
    public function referer(): string;
    public function timestamp(): int;              // $now ?? time()
    #[\NoDiscard] public function withFields(array $fields): self;
    #[\NoDiscard] public function withFormId(string $formId): self;
    public static function fromGlobals(?array $server = null, ?array $post = null, string $formId = 'default'): self;
    /** @return array<string, mixed> */
    public function toArray(): array;
}

enum CheckStatus: string
{
    case SPAM = 'spam';          // hard block, ignores the score
    case HAM = 'ham';            // no hard verdict; a positive score is a suspicion signal
    case UNCERTAIN = 'uncertain';// not enough data; contributes 0
    case ERROR = 'error';        // the check failed; fails open, contributes 0
}

final readonly class CheckOutcome
{
    /** @param array<string, mixed> $evidence */
    public function __construct(
        public string $check,
        public CheckStatus $status,
        public int $score = 0,        // 0..100
        public string $reason = '',
        public array $evidence = [],
    ) {}

    public static function ham(string $check, string $reason = ''): self;
    public static function suspicious(string $check, int $score, string $reason, array $evidence = []): self; // HAM + score
    public static function spam(string $check, string $reason, array $evidence = [], int $score = 100): self;
    public static function uncertain(string $check, string $reason, array $evidence = []): self;
    public static function error(string $check, string $reason): self;
    public function isFlagged(): bool;   // SPAM or score > 0
    /** @return array<string, mixed> */
    public function toArray(): array;
}

final readonly class Verdict
{
    public Status $status;      // FormSpamChecker\Status: Clean | Suspicious | Spam
    public int $score;          // capped 0..100
    /** @var list<CheckOutcome> */
    public array $outcomes;

    /** @param list<CheckOutcome> $outcomes */
    public static function fromOutcomes(array $outcomes, Config $config, bool $hardSpam, int $rawScore): self;
    public function isSpam(): bool;
    public function isSuspicious(): bool;
    public function isClean(): bool;
    /** @return list<string> */
    public function reasons(): array;
    /** @return list<CheckOutcome> */
    public function flagged(): array;
    /** @return array<string, mixed> */
    public function toArray(): array; // status, score, reasons, checks
    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self;
}
```

## Check contract

```php
namespace FormSpamChecker\Check;

interface SpamCheckInterface
{
    public function name(): string;                       // snake_case, stable, used in logs
    public function check(Data\RequestData $data): Data\CheckOutcome;
}
```

Rules:

- Checks are stateless per submission; mutable state lives in injected storage
  (`StorageInterface`, `CacheInterface`) or value objects read from config.
- A check must not perform I/O unless it is a clearly named network check
  (`abuseipdb`, `dnsbl`, `spf`, `dmarc`, `dkim`) and its config allows it.
- Network checks are registered last; `pipeline.stop_on_spam` (default `true`)
  stops the run on the first hard `SPAM`, saving quota.
- A throwing check is caught by the pipeline and recorded as `ERROR` (fail open).
- `HAM` with `score > 0` is the way to express "suspicious": the score is added
  to the submission total; `SPAM` forces the verdict regardless of the total.

## Pipeline

```php
final readonly class SpamPipeline
{
    /** @param list<SpamCheckInterface> $checks */
    public function __construct(public array $checks = []) {}

    #[\NoDiscard] public function add(SpamCheckInterface $check): self; // immutable append
    public function process(RequestData $data, Config $config): Verdict;
}
```

Aggregation (`Verdict::fromOutcomes`):

1. any `SPAM` outcome → `Status::Spam`;
2. else capped sum of scores `>= thresholds.spam` → `Status::Spam`;
3. else capped sum `>= thresholds.suspicious` → `Status::Suspicious`;
4. else `Status::Clean`.

## Abstractions (PSR-shaped, adapters included)

```php
namespace FormSpamChecker\Http;
readonly final class HttpRequest  { string $method; string $url; array $headers; string $body; float $timeout; }
readonly final class HttpResponse { int $status; array $headers; string $body; }
interface HttpClientInterface { public function send(HttpRequest $request): HttpResponse; }

namespace FormSpamChecker\Cache;
interface CacheInterface
{
    public function get(string $key): mixed;               // null when missing/expired
    public function set(string $key, mixed $value, int $ttl = 0): void;
    public function has(string $key): bool;
    public function delete(string $key): void;
}

namespace FormSpamChecker\Log;
interface LoggerInterface
{
    /** @param array<string, mixed> $context */
    public function log(string $level, string $message, array $context = []): void;
    /** @param array<string, mixed> $context */
    public function error(string $message, array $context = []): void;
    /** @param array<string, mixed> $context */
    public function warning(string $message, array $context = []): void;
    /** @param array<string, mixed> $context */
    public function info(string $message, array $context = []): void;
    /** @param array<string, mixed> $context */
    public function debug(string $message, array $context = []): void;
}

namespace FormSpamChecker\Dns;
interface ResolverInterface
{
    /** @return list<string> */
    public function txt(string $name): array;
    /** @return list<string> */
    public function a(string $name): array;
    /** @return list<string> MX host names, lowercased, no trailing dot */
    public function mx(string $name): array;
}
```

PSR adapters (`Psr18ClientAdapter`, `Psr16CacheAdapter`, `Psr6CacheAdapter`,
`Psr3LoggerAdapter`) reference `Psr\...` types only when the corresponding
interface is installed (`composer suggest`, `require-dev` in this repo). Nothing
in the runtime path loads them unless the user passes a PSR object.

## Configuration additions (all disabled by default)

Existing 1.x keys keep working unchanged. New sections:

```php
'pipeline'   => ['stop_on_spam' => true],
'http'       => ['timeout' => 2.0, 'user_agent' => 'PHP-Form-Spam-Checker/2.0'],
'cache'      => ['driver' => 'file', 'path' => ''],
'abuseipdb'  => ['enabled' => false, 'api_key' => '', 'threshold' => 90,
                 'cache_ttl' => 21600, 'timeout' => 2.0, 'max_age_days' => 30,
                 'fail_open' => true, 'circuit_breaker' => ['failures' => 3, 'cooldown' => 300]],
'dnsbl'      => ['enabled' => false, 'zones' => ['zen.spamhaus.org', 'bl.spamcop.net'],
                 'cache_ttl' => 3600, 'timeout' => 2, 'hit_score' => 100],
'spf'        => ['enabled' => false, 'fields' => ['email', 'personalEmail'],
                 'missing_score' => 10, 'lookup_limit' => 10, 'dns_ttl' => 3600],
'dmarc'      => ['enabled' => false, 'fields' => ['email', 'personalEmail'],
                 'missing_score' => 10, 'weak_policy_score' => 5, 'dns_ttl' => 3600],
'dkim'       => ['enabled' => false, 'required' => false],
'bayes'      => ['enabled' => false, 'storage_path' => '', 'threshold' => 0.92,
                 'min_documents' => 20, 'score_scale' => 100],
'behavioral' => [
    'honeypot'     => ['dynamic' => true, 'field_prefix' => '_hp_', 'secret' => '', 'missing_score' => 10],
    'js_challenge' => ['enabled' => false, 'field' => '_js', 'missing_score' => 15, 'min_ms' => 0],
],
'waf'        => ['enabled' => false, 'mode' => 'monitor', // off | monitor | block
                 'block_status' => 403, 'max_body_bytes' => 1048576,
                 'rules' => ['sql_injection' => true, 'xss' => true, 'path_traversal' => true,
                             'command_injection' => true, 'scanner' => true,
                             'header_injection' => true, 'protocol' => true,
                             'ip_reputation' => false, 'rate_limit' => false]],
'forms'      => [],
```

## Quality gates (all in CI, blocking)

| Gate | Command | Requirement |
|---|---|---|
| Formatting | `composer cs:check` | zero diffs (PSR-12/PER-CS2, risky rules whitelisted) |
| Static analysis | `composer phpstan` | `level: max`, strict rules, bleeding edge, zero errors |
| Taint analysis | `composer psalm` | `--taint-analysis`, zero errors |
| Tests | `composer test:strict` | zero failures/warnings/deprecations/risky |
| Coverage | `composer test:coverage` | reported; threshold enforced in CI (target 100 % for `src/`, documented exceptions only for environment adapters) |
| Syntax | `php -l` | all files |

Every module must ship tests in the same change. A module is not accepted
without: unit tests for every negative/positive branch, a fail-open test for
I/O errors, and a test proving no network call when disabled.
