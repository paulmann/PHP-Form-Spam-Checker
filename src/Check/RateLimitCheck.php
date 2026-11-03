<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Storage\StorageInterface;

/**
 * Durable per-IP rate limiting: counters survive worker restarts and are shared
 * between PHP-FPM workers through the storage abstraction.
 */
final readonly class RateLimitCheck implements SpamCheckInterface
{
    public function __construct(
        private Config $config,
        private StorageInterface $storage,
    ) {}

    public function name(): string
    {
        return 'rate_limit';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('rate_limit.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $ip = trim($data->ip);
        if ($ip === '') {
            return CheckOutcome::ham($this->name(), 'no client ip in context');
        }

        $max = max(1, $this->config->int('rate_limit.max', 8));
        $window = max(1, $this->config->int('rate_limit.window', 900));
        $perForm = $this->config->bool('rate_limit.per_form', true);

        $key = \sprintf('rl:%s:%s', $perForm ? $data->formId : '*', $ip);
        $count = $this->storage->increment($key, $window);

        if ($count <= $max) {
            return CheckOutcome::ham(
                $this->name(),
                \sprintf('%d/%d requests in %d s window', $count, $max, $window),
            );
        }

        return new CheckOutcome(
            $this->name(),
            CheckStatus::SPAM,
            $this->config->int('rate_limit.score', 100),
            \sprintf('rate limit exceeded: %d requests in %d s window (max %d)', $count, $window, $max),
            ['count' => $count, 'max' => $max, 'window' => $window],
        );
    }
}
