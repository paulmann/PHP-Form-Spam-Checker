<?php

declare(strict_types=1);

namespace FormSpamChecker\Security;

use Closure;
use FormSpamChecker\Config;
use FormSpamChecker\Storage\StorageInterface;
use Throwable;

/**
 * Application-level auto-ban.
 *
 * Every hard-spam verdict (or WAF block) records an abuse event for the client
 * IP. When the number of events inside `autoban.window` reaches
 * `autoban.threshold`, the IP is banned in the shared storage for
 * `autoban.ttl` seconds:
 *
 *   - `security/checks` short-circuits banned IPs with a hard SPAM verdict
 *     (see {@see \FormSpamChecker\Check\BanCheck});
 *   - the ban is reported to Fail2Ban (when configured), so the firewall can
 *     drop the IP before PHP is even involved.
 *
 * The app-level ban is fail-open by design: storage failures must never take a
 * form down, and a missing key simply means "not banned".
 */
final class AutoBan
{
    /**
     * @param Closure(): int|null $clock test hook
     */
    public function __construct(
        private readonly Config $config,
        private readonly StorageInterface $storage,
        private readonly ?Fail2Ban $fail2ban = null,
        private readonly ?Closure $clock = null,
    ) {}

    public function enabled(): bool
    {
        return $this->config->bool('autoban.enabled', false);
    }

    public function isBanned(string $ip): bool
    {
        if (!$this->validIp($ip)) {
            return false;
        }

        return $this->storage->get($this->banKey($ip)) !== null;
    }

    /**
     * Record one abusive event; returns true when this event banned the IP.
     */
    public function recordAbuse(string $ip, string $reason = 'spam', int $score = 0, string $formId = ''): bool
    {
        if (!$this->enabled() || !$this->validIp($ip) || $this->isBanned($ip)) {
            return false;
        }

        $threshold = max(1, $this->config->int('autoban.threshold', 5));
        $window = max(60, $this->config->int('autoban.window', 3600));

        $count = $this->storage->increment($this->abuseKey($ip), $window);

        if ($count < $threshold) {
            return false;
        }

        $this->ban($ip, $reason, $score, $formId);

        return true;
    }

    /**
     * Ban an IP immediately (also used by the CLI/tests).
     */
    public function ban(string $ip, string $reason = 'autoban', int $score = 0, string $formId = ''): void
    {
        if (!$this->validIp($ip)) {
            return;
        }

        $ttl = max(60, $this->config->int('autoban.ttl', 86400));

        $this->storage->set($this->banKey($ip), (string) $this->now(), $ttl);
        $this->storage->delete($this->abuseKey($ip));

        try {
            $this->fail2ban?->report($ip, $reason, $score, $formId);
        } catch (Throwable) {
            // Fail2Ban is a helper, never a dependency.
        }
    }

    public function unban(string $ip): void
    {
        if (!$this->validIp($ip)) {
            return;
        }

        $this->storage->delete($this->banKey($ip));
        $this->storage->delete($this->abuseKey($ip));
    }

    private function banKey(string $ip): string
    {
        return 'ban:' . $ip;
    }

    private function abuseKey(string $ip): string
    {
        return 'abuse:' . $ip;
    }

    private function validIp(string $ip): bool
    {
        return $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    private function now(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }
}
