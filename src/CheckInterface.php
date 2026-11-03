<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * A spam check.
 *
 * Implementations must be stateless with respect to the submission: all
 * mutable state (rate-limit counters, caches) lives in the injected storage.
 */
interface CheckInterface
{
    /**
     * Stable machine name used in verdicts and logs (snake_case).
     */
    public function name(): string;

    public function check(Submission $submission): CheckResult;
}
