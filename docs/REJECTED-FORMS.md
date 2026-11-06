# Registry of rejected (unsent) forms

A blocked form submission is normally lost: the drop-in guard answers it and
the application never sees the data. `FormSpamChecker\Integration\RejectedStore`
keeps every rejection instead — the full payload, the client and the exact
reason — so that a false positive can be reviewed and turned back into a real
submission.

This is the *registry*, not the verdict log. The two serve different purposes:

| | Verdict log (`log`) | Registry (`rejected`) |
|---|---|---|
| Purpose | statistics, tuning | recovering a lost lead |
| Payload | pseudonymised (`log.pii = false`) | **full raw payload** |
| Retention | log rotation | `rejected.retention_days` (30 by default) |
| Access | read the log file | masked CLI, `--reveal` for personal data |

The registry **deliberately stores personal data**, because a record without
the payload cannot be replayed. Its access control is the filesystem, the CLI
masking and the retention window — not redaction.

## What is stored

One JSON record per rejection (`<id>.json`), with:

- `id`, `version`, `status` (`new` | `replayed` | `ignored` | `expired`),
  `site`, `form`, `source` (`form` or `waf`), `reason` (`spam` | `waf` |
  `suspicious`), `would_reject` (a `suspicious` record never blocked);
- `ts` (ISO-8601 **with explicit offset**), `ts_utc` (same instant in UTC,
  `Z`) and `ts_epoch` — enough to sort and to correlate without mixing
  time zones;
- `verdict`: status, score, every reason and **all check outcomes** with
  evidence (form pipeline) or every WAF finding;
- `request`: method, URI, path, query, query string, scheme, host, URL and the
  replay-relevant headers (Host, Content-Type, User-Agent, Referer, Origin,
  Accept, Accept-Language, X-Requested-With);
- `client`: IP, User-Agent, Referer, Origin, Accept-Language;
- `payload`: `stored`, content type, raw body (base64 if binary), **all POST
  fields untrimmed with arrays preserved**, and upload metadata (field, name,
  type, size, error, SHA-256; stored bytes when `rejected.store_files` is on);
- `truncated` / `truncated_fields` when the hard byte limit was hit.

Example record (personal data masked):

```json
{
  "version": 1,
  "id": "20261106T001234123456-a1b2c3d4",
  "ts": "2026-11-06T03:12:34+03:00",
  "ts_utc": "2026-11-06T00:12:34Z",
  "ts_epoch": 1762387954,
  "status": "new",
  "site": "example.ru",
  "form": "lead",
  "source": "form",
  "reason": "spam",
  "would_reject": true,
  "verdict": {
    "status": "spam",
    "score": 60,
    "reasons": ["language: 1 name field(s) contain no Cyrillic letters"],
    "checks": [{"check": "language", "status": "ham", "score": 60, "reason": "1 name field(s) contain no Cyrillic letters", "evidence": {}}],
    "kind": "form"
  },
  "request": {
    "method": "POST",
    "uri": "/contact/?utm=letter",
    "url": "https://example.ru/contact/?utm=letter",
    "host": "example.ru",
    "scheme": "https",
    "headers": {"host": "example.ru", "content-type": "application/x-www-form-urlencoded", "user-agent": "Mozilla/5.0…"}
  },
  "client": {"ip": "203.0.113.77", "user_agent": "Mozilla/5.0…", "referer": "https://example.ru/contact/", "origin": "https://example.ru", "accept_language": "ru-RU,ru;q=0.9"},
  "payload": {
    "stored": true,
    "content_type": "application/x-www-form-urlencoded",
    "body": "",
    "body_bytes": 0,
    "fields": {"name": "John Smith", "email": "john@example.com", "phone": "+7 999 123-45-67", "message": "Need a quote"},
    "files": []
  },
  "truncated": false,
  "truncated_fields": []
}
```

## Configuration

```php
'config' => [
    'storage' => ['path' => '/var/www/lib/PHP-Form-Spam-Checker/var/sites/example.ru'],
    'rejected' => [
        'enabled' => true,               // default true: a blocked lead is kept
        'store_payload' => true,         // false: metadata + verdict only
        'path' => '',                    // default: <var>/rejected/<site>
        'retention_days' => 30,          // 0 disables the TTL
        'max_records_per_site' => 2000,  // oldest pruned first
        'max_bytes_per_record' => 262144,
        'store_files' => false,          // copy uploads for a multipart replay
        'capture_suspicious' => false,   // also keep "suspicious" (never blocked)
        'store_headers_secrets' => false,// keep Cookie/Authorization (never replayed)
    ],
],
```

The derived default path is `dirname(dirname(storage.path)) . '/rejected/<site>'`,
i.e. `var/rejected/<site>` for the shared guard — a top-level tree next to
`var/log`, not inside the per-site counter/cache tree, so permissions, backup
and retention can be managed independently.

`rejected.capture_suspicious` is off by default: a registry should grow on real
rejections, but "suspicious" submissions are exactly the borderline population
that is useful when tuning thresholds. Enable it temporarily, then disable it.

## Guard wiring

`FormGuard` writes a record after a spam verdict in `enforce` mode, before the
blocking response is returned. `WafGuard` does the same for a WAF block. Both
calls are fail-open: a registry error is logged and never changes the decision.
`evaluate()` and `buildResponse()` are side-effect free, and an explicit
`reject()` from a front controller captures too — exactly once per request.

## CLI

```bash
php bin/rejected-forms list                       # newest first, masked triage view
php bin/rejected-forms list --site=example.ru --status=new --since=2026-11-01 --json
php bin/rejected-forms show <id>                  # masked
php bin/rejected-forms show <id> --reveal         # raw personal data (on purpose)
php bin/rejected-forms replay <id>                # dry run: prints what would be sent
php bin/rejected-forms replay <id> --confirm      # send it (same host only)
php bin/rejected-forms replay <id> --confirm --url=https://example.ru/lead.php --allow-host-change
php bin/rejected-forms ignore <id> --reason="duplicate of ticket 42"
php bin/rejected-forms purge --older-than=30      # dry run
php bin/rejected-forms purge --older-than=30 --confirm
```

`list` shows the triage columns without revealing values: id, UTC timestamp,
site, form, score, status, whether an e-mail/phone field is present, masked IP
and the first reason. `--json` returns `{"count":N,"records":[…]}`.

Every command accepts `--config=PATH` (or `SPAM_CHECKER_CONFIG`),
`--path=REGISTRY_ROOT` and `--site=SITE`. Exit codes: `0` success, `1` record or
operation refused, `2` usage error, `3` storage/transport error.

`replay` is a dry run by default and prints the original rejection reason before
sending. Safety rules: the target defaults to the record's own URL; a different
host is refused unless `--allow-host-change` is passed; Cookie and Authorization
are never replayed; uploads are replayed as `multipart/form-data` only from
stored bytes, and a record whose files were not stored is refused instead of
being sent without its attachments.

## Permissions and operations

- Registry directories are created `0700`, files `0600`, and a `.htaccess`
  (`Require all denied`) is written at the root. Keep the tree **outside the
  document root**: `.htaccess` is Apache-only and no substitute for a location
  outside the web root under nginx/other servers.
- The registry is a recovery store, not an archive: `retention_days` and
  `max_records_per_site` bound it. A purge removes records by filesystem
  mtime (`--older-than=DAYS`, dry run without `--confirm`).
- Back it up separately if "never lose a lead" is a business rule; the payloads
  are personal data, so treat a backup with the same care.
- On a multi-server setup the guard must see the same directory (shared volume),
  or every server keeps its own registry.

## Timestamps and time zones

`ts` is local time **with an offset** (e.g. `2026-11-06T03:12:34+03:00`) and
`ts_utc` is the same instant in UTC (`2026-11-06T00:12:34Z`). They are never
interchangeable: a timestamps column filled with local time but labelled `Z`
(observed in another production system, where `created_at` drifted three hours
from an event log) makes incident timelines unusable. Sort on `ts_epoch` or
`ts_utc`; present `ts` when showing an operator their local clock.

## Testing

`tests/Integration/RejectedStoreTest.php` covers capture, payload fidelity,
truncation, pruning, retention purge, the status lifecycle, upload metadata and
both guard wires; `tests/Integration/ReplayRequestTest.php` covers request
reconstruction, dry-run default, secret stripping, host validation and multipart
replay; `tests/Unit/RejectedFormsCommandTest.php` covers the CLI. A clean
submission and a `suspicious` verdict without `capture_suspicious` are the
false-positive decoys: they must not create a record.
