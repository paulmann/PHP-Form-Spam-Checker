# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `2.1.x` | yes |
| `2.0.x` | security fixes only |
| `1.x` | no — upgrade to 2.1 |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately via GitHub Security Advisories
("Security" → "Report a vulnerability" on the repository) or by e-mail to the
maintainer listed on the GitHub profile. Include:

- affected version/commit;
- a minimal reproduction (payload, configuration, PHP version);
- impact assessment (false negative, false positive, DoS, RCE, data leak,
  network egress, WAF bypass).

You will receive an acknowledgement within 72 hours and a remediation plan.

## Security model

The checker processes **untrusted input** from two layers: form submissions
(fields, context) and, when the WAF is enabled, the whole HTTP request (method,
URI, query, headers, cookies, body). Defensive rules that apply to everything
in 2.0:

- no `eval`, no shell execution, no `unserialize()`, no dynamic includes from
  user input;
- no SQL and no template rendering — the library returns value objects;
- plain PHP 8.5, no runtime Composer dependency; parser and analyser
  dependencies are `require-dev` only;
- a check or rule that throws is caught and **fails open**: a broken check never
  blocks a form, a broken WAF rule never blocks a request;
- every network lookup is opt-in through configuration and can be disabled per
  form.

### Time-trap and challenge tokens

- The time-trap token is HMAC-SHA-256 over a canonical payload, base64url
  encoded, compared with `hash_equals`, and bound to the form id.
- The JS challenge token is the same construction plus a numeric challenge; the
  answer is not a secret (the client must compute it), the signature prevents
  tokens being minted for another form or time.
- Secrets must be at least 16 characters (the time trap recommends 32+ random
  characters), stored outside the web root and never committed. A short secret
  is a configuration error that fails open — never a silently weak token.
- Dynamic honeypot names use
  `HMAC-SHA-256(secret, formId|hourBucket)`; the current and previous hour are
  accepted.

### Network egress

All network access is **disabled by default**. When enabled, exactly these
destinations are contacted:

| Module | Destination | Data sent | Cache |
|---|---|---|---|
| `abuseipdb` | `https://api.abuseipdb.com/api/v2/check` (HTTPS) | the client IP, `maxAgeInDays`, the API key in the `Key` header | outcome per IP for `cache_ttl` (6 h) |
| `dnsbl` | the configured DNSBL zones (`zen.spamhaus.org`, `bl.spamcop.net`) | the reversed client IP as a DNS name | answers via `CachedResolver` |
| `spf` | DNS TXT for the claimed e-mail domain | the domain name | answers via `CachedResolver` |
| `dmarc` | DNS TXT `_dmarc.<domain>` | the domain name | answers via `CachedResolver` |
| `waf` `ip_reputation` | whatever check is injected (typically AbuseIPDB) | only the client IP (a `RequestData` with empty fields is passed) | via that check |

No form content, message text, e-mail body or file is ever sent. DNS resolvers
are system resolvers unless you inject your own `ResolverInterface`; a
privacy-sensitive deployment can point them at a local resolver and audit the
zone list.

PSR adapters (`Psr18ClientAdapter`, `Psr16CacheAdapter`, `Psr6CacheAdapter`,
`Psr3LoggerAdapter`) are only used when the application passes a PSR object
explicitly; nothing loads them in the default runtime path.

### Secrets and keys

| Secret | Config key | Use |
|---|---|---|
| Time-trap / challenge HMAC | `time_trap.secret`, `behavioral.js_challenge.secret`, `behavioral.honeypot.secret` | signing, token binding, dynamic names |
| HTTP endpoint key | `endpoint.key` | `X-Spam-Checker-Key`, constant-time compared |
| AbuseIPDB key | `abuseipdb.api_key` | sent only to `api.abuseipdb.com` |

Rules:

- read secrets from the environment (`getenv()` in the config file) or from a
  PHP-FPM pool `env[…]` directive; never commit them;
- the CLI bridges accept `--config=` and `SPAM_CHECKER_CONFIG`, and the site
  configs are read by the web user — keep them `644` and free of credentials
  that the web user must not see;
- rotate the endpoint key and HMAC secrets on a schedule or after any suspected
  exposure. Rotating the HMAC secret invalidates in-flight time-trap tokens
  (users re-submit the form) and every dynamic honeypot name.

### Storage, cache and logs

- File storage writes small JSON files named `sha256(key).json` under
  `storage.path`, uses `flock` for atomic updates and garbage-collects expired
  entries. A storage key never becomes a path.
- The cache holds derived network answers, including **client IP addresses**
  (as cache keys that are hashed by the file adapter) and their reputation
  outcome. Treat `storage.path` as internal data: `0770`/`0775` with a group
  that only the web user belongs to, outside the document root.
- The verdict log pseudonymises the client IP (`sha256`, 16 hex) and redacts
  all field values unless `log.pii` is explicitly enabled; PII mode also honours
  `fields.exclude`.
- The WAF logs method, URI, client IP and rule reasons through `error_log()`.
  Evidence contains a truncated payload fragment or short metadata (rule,
  location, field name), never the whole body or a whole field value.
- The Bayesian model stores token counts and document counts only — never the
  training documents. The model file is written through the cache adapter and
  an unreadable model is treated as "untrained" (fail open).

### WAF

- Disabled by default; when enabled it starts in `monitor` mode. A blocked
  request receives `403` (configurable), `X-WAF: blocked`, `Cache-Control:
  no-store`.
- Administrative areas are protected by a default skip list; an explicit
  `waf_skip` replaces it. Never let a false positive block `/admin`, `/login`
  or an authenticated API.
- The request body is read once from `php://input` and capped by
  `waf.max_body_bytes` (default 1 MiB); multipart and binary bodies are excluded
  from content signature scanning.
- A request that the WAF cannot evaluate (configuration error, rule exception,
  storage failure for `rate_limit`, timeout) is allowed. Availability is
  preferred over blocking when the firewall itself is broken.
- The WAF is not a replacement for output encoding, prepared statements, CSRF
  protection or transport limits. A signature-based WAF raises the cost of
  automated abuse; it does not prove an application safe.

### Denial of service

- `length.max` / `length.hard_max` cap inspected field sizes.
- `endpoint.max_body_bytes` (default 256 KiB) caps the HTTP bridge body; the WAF
  caps its own body at `waf.max_body_bytes`.
- AbuseIPDB has a per-IP cache, an HTTP timeout (`abuseipdb.timeout`, default
  2 s), a `429` back-off without in-process retries, and a circuit breaker
  (3 consecutive failures → 5 min open) so a slow API cannot pin PHP workers.
- DNS lookups are cached and SPF evaluation is bounded by
  `spf.lookup_limit` (default 10, RFC 7208 budget).
- `pipeline.stop_on_spam` stops the run after the first hard spam verdict,
  skipping the network checks.

## Out of scope

- Spam that is indistinguishable from legitimate text (the library is a filter,
  not an oracle).
- Denial of service at the HTTP server layer (reduce with nginx limits; see
  [docs/WAF.md](docs/WAF.md#nginx--php-fpm)).
- Compromise of the host or of the application embedding the checker.
- WAF bypasses that require guessing the rule set or crafting payloads the
  documented rules do not claim to catch.
- A malicious administrator: someone who can edit `config/sites/<host>.php` can
  disable every protection.
