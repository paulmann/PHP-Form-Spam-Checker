# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately via GitHub Security Advisories
("Security" → "Report a vulnerability" on the repository) or by e-mail to the
maintainer listed on the GitHub profile. Include:

- affected version/commit;
- a minimal reproduction (payload, configuration, PHP version);
- impact assessment (false negative, false positive, DoS, RCE, data leak).

You will receive an acknowledgement within 72 hours and a remediation plan.

## Security model

The checker processes **untrusted input**:

- no network calls, no `eval`, no shell execution, no deserialisation;
- the time-trap token is HMAC-SHA-256 over a canonical payload, compared with
  `hash_equals`, and bound to the form id; the secret must be at least
  16 characters and should be stored outside the web root;
- file storage uses `flock`, hashed file names and JSON encoding — a key never
  becomes a path;
- the HTTP endpoint accepts POST only, enforces `endpoint.max_body_bytes`, and
  optionally requires a constant-time compared shared key;
- verdict logs pseudonymise the client IP and redact field values unless
  `log.pii` is explicitly enabled;
- a check that throws is caught by the pipeline and fails **open**: a broken
  check never blocks a form.

## Out of scope

- Spam that is indistinguishable from legitimate text (the library is a filter,
  not an oracle).
- Denial of service at the HTTP server layer (reduce with nginx limits).
- Compromise of the host or of the application embedding the checker.
