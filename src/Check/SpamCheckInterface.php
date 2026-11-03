<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * A single spam check with exactly one responsibility.
 *
 * Implementations must be stateless per submission: mutable state (counters,
 * caches) lives in injected storage or value objects read from configuration.
 */
interface SpamCheckInterface
{
    /**
     * Stable machine name used in verdicts and logs (snake_case).
     */
    public function name(): string;

    public function check(RequestData $data): CheckOutcome;
}
