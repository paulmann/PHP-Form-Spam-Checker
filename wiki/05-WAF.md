# WAF (HTTP Firewall)

The WAF inspects the whole HTTP request — method, URI, query string, form fields, cookies, headers,
raw body, and optionally client-IP reputation — before the application handles it. It is a library
plus a drop-in include, not a replacement for nginx or ModSecurity: it sees what PHP sees, runs in
the application's process, and answers with a plain HTTP response (`docs/WAF.md`, introduction).

It is **disabled by default** (`waf.enabled = false`). When enabled it starts in `monitor` mode;
switching to `block` is a deliberate, reviewed step (`docs/WAF.md`).

## Modes

| Mode | Behaviour |
|---|---|
| `off` | nothing is inspected |
| `monitor` | the verdict is computed and logged through `error_log()`; every request passes |
| `block` | a blocked request is answered (`waf.block_status`, default 403, header `X-WAF: blocked`) |

Table: `README.md`, section WAF, and `docs/WAF.md`, section Monitor to block rollout.

`Waf::inspect()` itself is mode-agnostic and has no opinion about HTTP; `WafGuard` decides whether
the verdict is logged or answered. That split is what makes the same rules usable from a library, a
drop-in include and the CLI bridge (`docs/WAF.md`, Architecture).

## Rules

Nine rules exist; all are enabled by default except `ip_reputation` and `rate_limit`. A rule's key is
`waf.rules.<name>` (`docs/WAF.md`, Rules matrix).

| Rule | Blocks | Severity | Hard |
|---|---|---|---|
| `sql_injection` | high-precision SQLi signatures in URI, query, fields, cookies and text body | 90 | yes |
| `xss` | `<script>`, event handlers, `javascript:`/`vbscript:`, `document.*` | 90 | yes |
| `path_traversal` | `../`/`..\` sequences anywhere, file-probe signatures on the request line | 85 | yes |
| `command_injection` | shell chaining, pipes into a shell, command substitution | 90 | yes |
| `scanner` | scanner-only paths (`/.env`, `/.git`, `/wp-login.php`, …) and attack-tool user agents | 80 | yes |
| `header_injection` | CR/LF/NUL in a header value, invalid header names, comma in `Host` | 80 | yes |
| `protocol` | disallowed method, negative or oversized body; soft: surprising `Content-Type`, bad `Host` | 70 | method/body only |
| `ip_reputation` | client IP whose injected reputation check returns a hard spam verdict | 100 | yes |
| `rate_limit` | more than `max` requests from one IP inside `window` | 80 | yes |

`ip_reputation` and `rate_limit` stay silent even when enabled until an `SpamCheckInterface` or a
`StorageInterface` is injected: the WAF never performs network or storage I/O it was not wired for
(`docs/WAF.md`, Architecture).

## Aggregation

1. any finding with `hard = true` → blocked;
2. otherwise the sum of severities, capped at 100, at or above `waf.thresholds.block` (default 60)
   → blocked;
3. at or above `waf.thresholds.suspicious` (default 30) → suspicious (logged, not blocked);
4. otherwise clean.

A rule that throws is logged and skipped — one broken rule must never turn the firewall into an
outage (`docs/WAF.md`, Request lifecycle).

## Rollout: monitor first

1. **Configure, keep it off.** Add the `waf` section and leave `enabled` false.
2. **Monitor.** `enabled = true`, `mode = monitor`. Review for one to three days.
3. **Tune.** Disable a rule or make it soft (`'hard' => false`) where a false hit appears. The rules
   are the same in every mode, so monitor-mode hits are exactly what block mode would block.
4. **Block.** `mode = block`.
5. **Watch.** Keep the skip list covering admin and authenticated areas: a false positive in `block`
   mode takes the form down for that visitor.

These five steps are `docs/WAF.md`, section Monitor to block rollout. Log lines look like:

```text
[waf] verdict example.ru POST /feedback.php from 203.0.113.10: mode=monitor status=blocked score=80 reasons=scanner: scanner User-Agent detected
```

## Deployment

Copy the module once (see [Integration](07-Integration)) and pick exactly **one** include
(`docs/INTEGRATION.md`, section 3):

```php
// A site that uses the form guard: guard.php runs the WAF first when waf.enabled is set.
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';

// A site without a form guard: the firewall alone.
require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
```

Do not require both — the request would be inspected twice. For a whole PHP-FPM pool, point
`auto_prepend_file` at `integrations/auto-prepend.php` when the pool also uses the form guard, or at
`integrations/waf.php` when it only needs the firewall (`README.md`, WAF). The WAF layer inside
`auto-prepend.php` runs independently of the legacy `auto` flag (`docs/INTEGRATION.md`, section 2).

The same `config/sites/<host>.php` file the form guard uses carries the WAF configuration
(`waf` section inside `config`, plus optional top-level `waf_mode`, `waf_skip`, `waf_match`,
`waf_response`) (`docs/WAF.md`, Site configuration).

### Matching and the skip list

- `waf_match` empty or absent → every request is inspected, except `waf_skip`;
- a non-empty `waf_skip` **replaces** the built-in list; an empty or absent list keeps the defaults:

```text
#^/bitrix/admin#i   #^/wp-admin#i   #^/admin(?:/|$)#i
#^/login(?:/|$)#i   #^/auth(?:/|$)#i   #^/cpanel(?:/|$)#i
```

Quote: `docs/WAF.md`, Matching semantics, which also states that both `uri` and `path` are tested
against each pattern. The default list is what protects `/admin`, `/login`, `/auth`, `/wp-admin`,
`/bitrix/admin` and `/cpanel` (`README.md`, WAF).

### Response behaviour

| Setting | Behaviour |
|---|---|
| default | `waf.block_status` (403), header `X-WAF: blocked`, `Cache-Control: no-store` |
| `waf_response = json` | `application/json` body `{"ok":false,"error":"waf_blocked","message":"…"}` |
| `waf_response = html` | minimal HTML block page |
| `waf_response = silent` | HTTP 200 with an empty body |
| `waf_response = auto` (default) | JSON for `Accept: application/json` or `/api`-like URIs, HTML otherwise |

The table is `docs/WAF.md`, Response behaviour. `monitor` mode never changes the response.

## Logging

The guard writes through `error_log()`; requests without findings are not logged, so a healthy site
stays quiet (`docs/WAF.md`, Logging):

```text
[waf] verdict <site> <METHOD> <uri> from <ip>: mode=<mode> status=<clean|suspicious|blocked> score=<0-100> reasons=<rule: reason; …>
[waf] blocked <site> <METHOD> <uri> from <ip>: mode=block score=<n> reasons=…
[waf] rule <name> failed, failing open: <message>
```

Evidence may contain a truncated match fragment, never the whole body or a whole field value
(`docs/WAF.md`; `SECURITY.md`, Storage, cache and logs).

## CLI bridge for non-PHP back ends

`bin/waf-check` runs the same rules out of process, which lets a Node, Go or Python server inspect a
request before its own code sees it (`docs/WAF.md`, CLI bridge):

```bash
php bin/waf-check --config=/var/www/lib/PHP-Form-Spam-Checker/config/sites/example.ru.php \
  --json='{"method":"POST","uri":"/api/lead","ip":"203.0.113.10",
           "headers":{"host":"example.ru","content-type":"application/json",
                      "user-agent":"Mozilla/5.0"},
           "cookies":{},"query":{},"body":"{\"email\":\"a@b.c\"}",
           "fields":{"email":"a@b.c"},"form":"lead"}'
```

STDOUT carries one JSON object, diagnostics go to STDERR, and the exit codes are `0` allow, `2`
block, `3` error; a disabled WAF answers `{"status":"disabled","blocked":false}` (`docs/WAF.md`).

Always pass `host` and `content-type` in a textual caller's payload: the `protocol` rule scores a
missing `Host` (25) and a missing `Content-Type` on a body-carrying method (40) as soft findings,
and with the default block threshold of 60 that combination can block a request that is not an
attack (`docs/WAF.md`, CLI bridge).

## Limits and non-goals

- No response inspection, no TLS, no connection throttling, no protection for static files served
  without PHP (`docs/WAF.md`, Limits and non-goals).
- PHP folds repeated header lines before user code runs, so the WAF does not see original header
  framing; it inspects the folded value (`docs/WAF.md`, Threat model).
- Uploaded file bytes are not pattern-scanned; a multipart body is treated as binary.
- The WAF never rewrites or sanitises input: prepared statements, output encoding and CSRF
  protection remain the application's responsibility.
- A signature-based WAF raises the cost of automated abuse; it does not prove an application safe.

## Next

- [Fail2Ban and Auto-Ban](06-Fail2Ban-And-AutoBan) — turn hard blocks into firewall bans.
- [Integration](07-Integration) — which include to use on which site.
