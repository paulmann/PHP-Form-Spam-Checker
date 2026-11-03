<?php

declare(strict_types=1);

namespace FormSpamChecker\Data;

use InvalidArgumentException;

/**
 * Rich result of a single check: status + score + human-readable reason and
 * structured evidence that explains the decision.
 */
final readonly class CheckOutcome
{
    /**
     * @param array<string, mixed> $evidence
     */
    public function __construct(
        public string $check,
        public CheckStatus $status,
        public int $score = 0,
        public string $reason = '',
        public array $evidence = [],
    ) {
        if ($score < 0 || $score > 100) {
            throw new InvalidArgumentException(\sprintf(
                'Check score must be between 0 and 100, %d given for "%s".',
                $score,
                $check,
            ));
        }
    }

    public static function ham(string $check, string $reason = ''): self
    {
        return new self($check, CheckStatus::HAM, 0, $reason);
    }

    /**
     * A suspicion signal: HAM status with a positive score.
     *
     * @param array<string, mixed> $evidence
     */
    public static function suspicious(string $check, int $score, string $reason, array $evidence = []): self
    {
        return new self($check, CheckStatus::HAM, max(1, $score), $reason, $evidence);
    }

    /**
     * @param array<string, mixed> $evidence
     */
    public static function spam(string $check, string $reason, array $evidence = [], int $score = 100): self
    {
        return new self($check, CheckStatus::SPAM, max(1, $score), $reason, $evidence);
    }

    /**
     * @param array<string, mixed> $evidence
     */
    public static function uncertain(string $check, string $reason, array $evidence = []): self
    {
        return new self($check, CheckStatus::UNCERTAIN, 0, $reason, $evidence);
    }

    public static function error(string $check, string $reason): self
    {
        return new self($check, CheckStatus::ERROR, 0, 'check error (fail open): ' . $reason);
    }

    public function isFlagged(): bool
    {
        return $this->status->isHardSpam() || $this->score > 0;
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
