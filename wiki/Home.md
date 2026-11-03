# PHP Form Spam Checker

A layered, dependency-free anti-spam pipeline and HTTP firewall for any PHP form: local heuristics
first, then behavioural signals, IP reputation, DNS blocklists, mail-domain authentication and a
Bayesian classifier, with an optional WAF over the whole HTTP request. No captcha, no runtime
Composer dependencies, and every verdict carries evidence — which checks ran, with which scores,
and why (`README.md`, opening paragraph).

![PHP Form Spam Checker](https://github.com/paulmann/PHP-Form-Spam-Checker/raw/main/assets/social-preview.png)

Version 2.1 (released 2026-11-03 according to `CHANGELOG.md`, section `[2.1.0]`) keeps the 2.0
architecture and adds the firewall bridge and deployment hardening:

- **Fail2Ban bridge** — every hard-spam verdict and every WAF block appends one timestamped
  `PHPFSC BAN ip=…` line to a per-site log, ready for a Fail2Ban filter and jail.
- **Application auto-ban** — the `autoban` check rejects an IP before any other check after N hard
  events inside a window.
- **AbuseIPDB `threshold = 100`** deployment guidance: only IPs whose confidence score is exactly
  100 are treated as spam by the reference deployments (the library default stays 90).

## Start here

| Step | Page | Why |
|---|---|---|
| 1 | [Installation](01-Installation) | requirements, Composer or a plain copy, verification |
| 2 | [Quick Start](02-Quick-Start) | one protected form, the CLI probe and the HTTP endpoint |
| 3 | [Configuration](03-Configuration) | defaults, per-form overrides, storage and logging |

## Protection

| Topic | Page | What it covers |
|---|---|---|
| Checks | [Checks](04-Checks) | the 20 pipeline checks, scores, statuses, false positives, custom checks |
| HTTP firewall | [WAF](05-WAF) | the 9 request rules, monitor-to-block rollout, deployment, CLI bridge |
| Firewall bans | [Fail2Ban and Auto-Ban](06-Fail2Ban-And-AutoBan) | `PHPFSC BAN` lines, the jail, the application-level ban |

## Operations

| Task | Page | What it covers |
|---|---|---|
| Deploy next to a site | [Integration](07-Integration) | library, shared module, drop-in WAF, CLI bridges, HTTP endpoint |
| Upgrade a 1.x install | [Migration from 1.x](08-Migration-1-to-2) | kept contracts, moved classes, rollback, checklist |

## What this wiki is

A manual for the people who install and run the library. It is organised by task, not by source
file, and it does not repeat the README. Numbers are quoted together with the repository document
and section they come from; when a page and the source disagree, the source wins and the mismatch
is worth a bug report.

The upstream documents remain authoritative:

| Document | Contents |
|---|---|
| [README.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/README.md) | overview, feature table, default scores |
| [AGENTS.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/AGENTS.md) | non-interactive operational contract |
| [docs/CONFIG.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/docs/CONFIG.md) | full configuration tree |
| [docs/CHECKS.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/docs/CHECKS.md) | check semantics and false positives |
| [docs/WAF.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/docs/WAF.md) | threat model, rules matrix, rollout |
| [docs/INTEGRATION.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/docs/INTEGRATION.md) | wiring guide (also available in Russian) |
| [docs/MIGRATION-1-to-2.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/docs/MIGRATION-1-to-2.md) | 1.x compatibility and rollback |
| [SECURITY.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/SECURITY.md) | security model, network egress, secrets |
| [CHANGELOG.md](https://github.com/paulmann/PHP-Form-Spam-Checker/blob/main/CHANGELOG.md) | release notes |

## Project links

- [Repository](https://github.com/paulmann/PHP-Form-Spam-Checker)
- [Releases](https://github.com/paulmann/PHP-Form-Spam-Checker/releases)
- [Issues](https://github.com/paulmann/PHP-Form-Spam-Checker/issues)
- [Security advisories](https://github.com/paulmann/PHP-Form-Spam-Checker/security/advisories)
- License: MIT (`LICENSE`, `composer.json`)

## Next

Begin with [Installation](01-Installation), or go straight to [Quick Start](02-Quick-Start) if the
library is already present.
