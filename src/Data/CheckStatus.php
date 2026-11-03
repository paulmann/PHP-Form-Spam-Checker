<?php

declare(strict_types=1);

namespace FormSpamChecker\Data;

/**
 * Categorical result of a single check.
 *
 * `HAM` with a positive score is how a check expresses "suspicious": the score
 * is added to the submission total and the thresholds decide. `SPAM` is a hard
 * verdict that blocks the submission regardless of the numeric total.
 */
enum CheckStatus: string
{
    case SPAM = 'spam';
    case HAM = 'ham';
    case UNCERTAIN = 'uncertain';
    case ERROR = 'error';

    public function label(): string
    {
        return match ($this) {
            self::SPAM => 'spam',
            self::HAM => 'ham',
            self::UNCERTAIN => 'uncertain',
            self::ERROR => 'error',
        };
    }

    public function isHardSpam(): bool
    {
        return $this === self::SPAM;
    }
}
