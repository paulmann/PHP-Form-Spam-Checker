<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * Result of a single check.
 *
 * `score` is the contribution of the check to the submission total, 0..100.
 * A check that returns Status::Spam makes the whole submission spam even when
 * the aggregated score would stay below the threshold.
 */
final class CheckResult
{
    /**
     * @param array<string, mixed> $evidence
     */
    public function __construct(
        public readonly string $check,
        public readonly Status $status,
        public readonly int $score,
        public readonly string $reason = '',
        public readonly array $evidence = [],
    ) {
        if ($score < 0 || $score > 100) {
            throw new \InvalidArgumentException(sprintf(
                'Check score must be between 0 and 100, %d given for "%s".',
                $score,
                $check,
            ));
        }
    }

    public static function clean(string $check, string $reason = ''): self
    {
        return new self($check, Status::Clean, 0, $reason);
    }

    /**
     * @param array<string, mixed> $evidence
     */
    public static function suspicious(string $check, int $score, string $reason, array $evidence = []): self
    {
        return new self($check, Status::Suspicious, max(1, $score), $reason, $evidence);
    }

    /**
     * @param array<string, mixed> $evidence
     */
    public static function spam(string $check, string $reason, array $evidence = [], int $score = 100): self
    {
        return new self($check, Status::Spam, max(1, $score), $reason, $evidence);
    }

    public function isFlagged(): bool
    {
        return $this->status->isFlagged();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'status' => $this->status->value,
            'score' => $this->score,
            'reason' => $this->reason,
            'evidence' => $this->evidence,
        ];
    }
}
