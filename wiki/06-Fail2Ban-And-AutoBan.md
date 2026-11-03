# Fail2Ban and Auto-Ban

Two optional layers turn repeated abuse into a ban. Both are disabled by default, both fail open,
and neither changes a verdict on its own (`README.md`, Fail2Ban and auto-ban):

| Layer | What it does | Where the state lives |
|---|---|---|
| **Fail2Ban bridge** | appends one `PHPFSC BAN …` line per hard event; a Fail2Ban filter and jail turn the lines into a firewall ban | a log file the jail follows |
| **Application auto-ban** | counts hard events per IP and rejects the IP in the pipeline before any other check | the library's own storage (`storage.*`) |

The bridge ships in 2.1 as `FormSpamChecker\Security\Fail2Ban`; the auto-ban is the `autoban`
pipeline check (`CHANGELOG.md`, `[2.1.0]` Added).

## What the bridge writes

One sanitized line per hard event, with an ISO-8601 timestamp first
(`docs/WAF.md`, Fail2Ban; `CHANGELOG.md`, `[2.1.0]` Security):

```text
2026-11-03T22:35:00+03:00 PHPFSC BAN ip=203.0.113.5 site=example.ru form=register score=100 reason=spam:keywords
```

Fields: `ip`, `site`, `form`, `score`, `reason`. Lines are LF-only, field values are token-sanitized
so no whitespace or newline can be injected, and the file is appended with `LOCK_EX`. A reporting
error never changes a verdict. The leading ISO-8601 timestamp exists so the jail needs no
"match without timestamp" fallback — `datepattern = ^%Y-%m-%dT%H:%M:%S%z`, as recorded in
`CHANGELOG.md`, `[2.1.0]` Security.

Which events are reported is a configuration choice: every hard-spam verdict from the form
pipeline, every hard WAF block, or both (`emit_on`), filtered by a minimum score (`min_score`).

```php
'fail2ban' => [
    'enabled' => true,
    'log_path' => __DIR__ . '/../var/log/sites/' . $site . '.f2b.log',
    'site' => $site,
    'emit_on' => 'both',   // spam | waf | both
    'min_score' => 60,
],
```

Quote: `README.md`, Fail2Ban and auto-ban. The `fail2ban.*` keys and defaults are tabulated in
`docs/CONFIG.md`, section Fail2Ban and auto-ban (2.1):

| Key | Default | Meaning |
|---|---|---|
| `fail2ban.enabled` | `false` | write `PHPFSC BAN …` lines |
| `fail2ban.log_path` | `storage/fail2ban.log` | file the jail follows; site configs use `var/log/sites/<site>.f2b.log` |
| `fail2ban.site` | `''` | token written into `site=` |
| `fail2ban.emit_on` | `both` | report form spam, WAF blocks, or both |
| `fail2ban.min_score` | `60` | minimum verdict or block score to report |

## The jail

Fail2Ban filter `/etc/fail2ban/filter.d/php-form-spam-checker.conf`, reproduced verbatim from
`docs/WAF.md`, section Fail2Ban:

```ini
[Definition]
datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z
failregex = PHPFSC BAN ip=<HOST> .*$
ignoreregex =
```

The jail in `/etc/fail2ban/jail.d/php-form-spam-checker.local` bans only HTTP and HTTPS so SSH is
never affected; keep administrative hosts in `ignoreip` (`docs/WAF.md`, Fail2Ban):

```ini
[php-form-spam-checker]
enabled  = true
filter   = php-form-spam-checker
logpath  = /var/www/lib/PHP-Form-Spam-Checker/var/log/sites/*.f2b.log
maxretry = 1
findtime = 3600
bantime  = 86400
action   = iptables-multiport[name=PHPFSC, port="http,https"]
ignoreip = 127.0.0.1/8 ::1 <admin-ip>
```

`maxretry = 1` matches the fact that a single hard event is already a deliberate decision by the
pipeline or the WAF. Verify the filter against a sample log before reloading Fail2Ban:

```bash
fail2ban-regex /path/to/sample.log php-form-spam-checker
```

Command and the advice to verify before reloading: `docs/WAF.md`, Fail2Ban.

## Application auto-ban

The `autoban` check is the fallback for hosts without Fail2Ban: after N hard events inside a window
the IP is stored as banned for a TTL, and the check rejects it before any other check runs
(`README.md`, Fail2Ban and auto-ban).

```php
'autoban' => ['enabled' => true, 'threshold' => 5, 'window' => 3600, 'ttl' => 86400],
```

| Key | Default | Meaning |
|---|---|---|
| `autoban.enabled` | `false` | enable the application-level ban |
| `autoban.threshold` | `5` | hard events inside the window before the ban |
| `autoban.window` | `3600` | counting window, seconds |
| `autoban.ttl` | `86400` | ban duration, seconds |

Defaults and meanings: `docs/CONFIG.md`, section Fail2Ban and auto-ban (2.1). Banned IPs live in the
same storage as rate-limit counters, so a `ban:<ip>` entry expires with `autoban.ttl`; `AutoBan::unban()`
removes an entry, and a failed storage call never blocks a form (`docs/CONFIG.md`).

Because storage is shared, an autoban is visible to every process that reads the same `storage.path`
— that is what makes it work across PHP-FPM workers (`docs/CONFIG.md`, Storage and cache paths).

## AbuseIPDB threshold for hardened deployments

The 2.1 deployment guidance recommends `'threshold' => 100` for AbuseIPDB: only IPs whose
confidence score is exactly 100 are treated as hard spam. The library default stays 90, and a
per-form override can raise it for a single form (`README.md`, AbuseIPDB setup; `CHANGELOG.md`,
`[2.1.0]` Added, Deployment guidance).

```php
'abuseipdb' => [
    'enabled' => true,
    'api_key' => getenv('ABUSEIPDB_KEY') ?: '',
    'threshold' => 100,      // reference deployments: only confidence 100 becomes hard spam
    'cache_ttl' => 21600,    // 6 h per-IP cache: a burst costs one query
    'fail_open' => true,
    'circuit_breaker' => ['failures' => 3, 'cooldown' => 300],
],
```

The comment values come from `README.md`, AbuseIPDB setup and `docs/CONFIG.md`, Full default tree.
The trade-off is explicit: a higher threshold means fewer blocked submissions and fewer false
positives on shared NAT addresses; a lower one blocks more aggressively. A ban derived from a
Reputation verdict therefore inherits that decision — which is why `fail2ban.min_score` (60 by
default) and `emit_on` are worth reviewing before the jail is enabled.

## Order of events on one request

1. `integrations/guard.php` runs the WAF layer when `waf.enabled` is set, then the form pipeline
   (`docs/INTEGRATION.md`, Fail2Ban and auto-ban).
2. A hard event from either layer is written to `fail2ban.log_path` when the bridge is enabled, and
   `autoban` counts it when the auto-ban is enabled.
3. The next request from that IP is rejected by the `autoban` check with a hard SPAM verdict — before
   any other check — or by the firewall ban created by the jail.

Keep `log_path` writable by the PHP user. Site configurations default it to
`var/log/sites/<site>.f2b.log`; the module default is `storage/fail2ban.log` (`docs/CONFIG.md`,
Fail2Ban and auto-ban (2.1)).

## Next

- [Integration](07-Integration) — where `guard.php` sits and how a site is configured.
- [WAF](05-WAF) — what counts as a hard WAF block.
