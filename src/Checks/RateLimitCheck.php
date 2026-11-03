<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Storage\StorageInterface;
use FormSpamChecker\Submission;

/**
 * Durable per-IP rate limiting.
 *
 * Unlike an in-process counter this survives PHP-FPM worker restarts and is
 * shared between workers, because counters live in StorageInterface (files by
 * default). The window is fixed: the first request opens it, the counter and
 * expiry are stored atomically.
 */
final class RateLimitCheck implements CheckInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly StorageInterface $storage,
    ) {
    }

    public function name(): string
    {
        return 'rate_limit';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('rate_limit.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $ip = trim($submission->context->ip);
        if ($ip === '') {
            return CheckResult::clean($this->name(), 'no client ip in context');
        }

        $max = max(1, $this->config->int('rate_limit.max', 8));
        $window = max(1, $this->config->int('rate_limit.window', 900));
        $perForm = $this->config->bool('rate_limit.per_form', true);

        $key = sprintf('rl:%s:%s', $perForm ? $submission->formId : '*', $ip);
        $count = $this->storage->increment($key, $window);

        if ($count <= $max) {
            return CheckResult::clean(
                $this->name(),
                sprintf('%d/%d requests in %d s window', $count, $max, $window),
            );
        }

        return CheckResult::spam(
            $this->name(),
            sprintf('rate limit exceeded: %d requests in %d s window (max %d)', $count, $window, $max),
            ['count' => $count, 'max' => $max, 'window' => $window],
            $this->config->int('rate_limit.score', 100),
        );
    }
}
