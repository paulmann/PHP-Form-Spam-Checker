<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Storage\StorageInterface;
use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Optional per-IP request-rate limit.
 *
 * Counters live in the injected {@see StorageInterface} (files by default), so
 * the limit is shared between PHP-FPM workers and survives a restart. The key
 * is the client IP plus the rule name; the window is fixed and opens on the
 * first request. Without storage the rule stays silent: a WAF must not perform
 * I/O it cannot do safely.
 */
final class RateLimitRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 80;

    protected const bool DEFAULT_HARD = true;

    public function __construct(
        Config $config,
        private readonly ?StorageInterface $storage = null,
    ) {
        parent::__construct($config);
    }

    public function name(): string
    {
        return 'rate_limit';
    }

    protected function defaultEnabled(): bool
    {
        return false;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $storage = $this->storage;

        if ($storage === null) {
            return null;
        }

        $ip = trim($request->ip);

        if ($ip === '') {
            return null;
        }

        $max = max(1, $this->intOption('max', 120));
        $window = max(1, $this->intOption('window', 60));

        $count = $storage->increment('waf:' . $this->name() . ':' . $ip, $window);

        if ($count <= $max) {
            return null;
        }

        return $this->finding(
            sprintf('rate limit exceeded: %d requests in %d s window (max %d)', $count, $window, $max),
            'ip',
            ['count' => $count, 'max' => $max, 'window' => $window],
            null,
            true,
        );
    }

    private function intOption(string $key, int $default): int
    {
        $value = $this->option($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
