<?php

declare(strict_types=1);

namespace FormSpamChecker\Data;

use FormSpamChecker\Config;
use FormSpamChecker\Status;

/**
 * Final verdict for one submission: status, capped score and every executed
 * check outcome (so a decision can always be explained after the fact).
 */
final readonly class Verdict
{
    /**
     * @param list<CheckOutcome> $outcomes
     */
    public function __construct(
        public Status $status,
        public int $score,
        public array $outcomes = [],
    ) {
        if ($score < 0 || $score > 100) {
            throw new \InvalidArgumentException(sprintf('Verdict score must be between 0 and 100, %d given.', $score));
        }
    }

    /**
     * @param list<CheckOutcome> $outcomes
     */
    public static function fromOutcomes(array $outcomes, Config $config, bool $hardSpam, int $rawScore): self
    {
        $spamThreshold = $config->int('thresholds.spam', 60);
        $suspiciousThreshold = $config->int('thresholds.suspicious', 30);
        $score = min(100, $rawScore);

        if ($hardSpam || $score >= $spamThreshold) {
            return new self(Status::Spam, $hardSpam ? max($score, 1) : $score, $outcomes);
        }

        if ($score >= $suspiciousThreshold) {
            return new self(Status::Suspicious, $score, $outcomes);
        }

        return new self(Status::Clean, $score, $outcomes);
    }

    public static function clean(): self
    {
        return new self(Status::Clean, 0);
    }

    public static function spam(int $score = 100): self
    {
        return new self(Status::Spam, $score);
    }

    public function isSpam(): bool
    {
        return $this->status === Status::Spam;
    }

    public function isSuspicious(): bool
    {
        return $this->status === Status::Suspicious;
    }

    public function isClean(): bool
    {
        return $this->status === Status::Clean;
    }

    /**
     * @return list<string>
     */
    public function reasons(): array
    {
        $reasons = [];
        foreach ($this->flagged() as $outcome) {
            $reasons[] = $outcome->reason !== ''
                ? sprintf('%s: %s', $outcome->check, $outcome->reason)
                : $outcome->check;
        }

        return $reasons;
    }

    /**
     * @return list<CheckOutcome>
     */
    public function flagged(): array
    {
        return array_values(array_filter(
            $this->outcomes,
            static fn (CheckOutcome $outcome): bool => $outcome->isFlagged(),
        ));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status->value,
            'score' => $this->score,
            'reasons' => $this->reasons(),
            'checks' => array_map(
                static fn (CheckOutcome $outcome): array => $outcome->toArray(),
                $this->outcomes,
            ),
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $status = Status::tryFrom((string) ($data['status'] ?? ''))
            ?? throw new \InvalidArgumentException('Verdict array has an unknown status.');

        $outcomes = [];
        foreach ((array) ($data['checks'] ?? []) as $check) {
            if (!is_array($check)) {
                continue;
            }

            $checkStatus = CheckStatus::tryFrom((string) ($check['status'] ?? ''));

            $outcomes[] = new CheckOutcome(
                check: (string) ($check['check'] ?? 'unknown'),
                status: $checkStatus ?? CheckStatus::HAM,
                score: (int) ($check['score'] ?? 0),
                reason: (string) ($check['reason'] ?? ''),
                evidence: (array) ($check['evidence'] ?? []),
            );
        }

        return new self($status, (int) ($data['score'] ?? 0), $outcomes);
    }
}
