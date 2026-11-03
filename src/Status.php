<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * Overall status of a submission or of a single check.
 *
 * A check contributes a status *and* a score; the pipeline aggregates scores
 * against the configured thresholds and lets an explicit Spam verdict from a
 * hard check win regardless of the numeric total.
 */
enum Status: string
{
    case Clean = 'clean';
    case Suspicious = 'suspicious';
    case Spam = 'spam';

    public function isFlagged(): bool
    {
        return $this !== self::Clean;
    }

    public function isSpam(): bool
    {
        return $this === self::Spam;
    }

    public function isClean(): bool
    {
        return $this === self::Clean;
    }

    public function label(): string
    {
        return match ($this) {
            self::Clean => 'clean',
            self::Suspicious => 'suspicious',
            self::Spam => 'spam',
        };
    }
}
