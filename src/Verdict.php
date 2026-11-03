<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * Final verdict for a submission.
 *
 * The verdict keeps every check result so that a decision can be explained
 * after the fact: "why was this blocked" is answered by the evidence array.
 */
final class Verdict
{
    /**
     * @param list<CheckResult> $results
     */
    public function __construct(
        public readonly Status $status,
        public readonly int $score,
        public readonly array $results = [],
    ) {
        if ($score < 0 || $score > 100) {
            throw new \InvalidArgumentException(sprintf('Verdict score must be between 0 and 100, %d given.', $score));
        }
    }

    /**
     * Aggregate check results into a verdict.
     *
     * Rules, in order:
     *  1. any check that explicitly says Spam wins (hard evidence);
     *  2. the capped sum of scores >= thresholds.spam is spam;
     *  3. the capped sum of scores >= thresholds.suspicious is suspicious;
     *  4. otherwise clean.
     *
     * @param list<CheckResult> $results
     */
    public static function fromResults(array $results, Config $config): self
    {
        $spamThreshold = $config->int('thresholds.spam', 60);
        $suspiciousThreshold = $config->int('thresholds.suspicious', 30);

        $score = 0;
        $hasSpam = false;

        foreach ($results as $result) {
            if ($result->status->isSpam()) {
                $hasSpam = true;
            }
            $score += $result->score;
        }

        $score = min(100, $score);

        if ($hasSpam || $score >= $spamThreshold) {
            return new self(Status::Spam, max($score, $hasSpam ? max(1, $score) : 0), $results);
        }

        if ($score >= $suspiciousThreshold) {
            return new self(Status::Suspicious, $score, $results);
        }

        return new self(Status::Clean, $score, $results);
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
     * Human-readable reasons of the checks that flagged the submission.
     *
     * @return list<string>
     */
    public function reasons(): array
    {
        $reasons = [];
        foreach ($this->results as $result) {
            if ($result->isFlagged()) {
                $reasons[] = $result->reason !== ''
                    ? sprintf('%s: %s', $result->check, $result->reason)
                    : $result->check;
            }
        }

        return $reasons;
    }

    /**
     * @return list<CheckResult>
     */
    public function flagged(): array
    {
        return array_values(array_filter($this->results, static fn (CheckResult $r): bool => $r->isFlagged()));
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
            'checks' => array_map(static fn (CheckResult $r): array => $r->toArray(), $this->results),
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $status = Status::tryFrom((string) ($data['status'] ?? ''))
            ?? throw new \InvalidArgumentException('Verdict array has an unknown status.');

        $results = [];
        foreach ((array) ($data['checks'] ?? []) as $check) {
            if (!is_array($check)) {
                continue;
            }
            $results[] = new CheckResult(
                check: (string) ($check['check'] ?? 'unknown'),
                status: Status::tryFrom((string) ($check['status'] ?? 'clean')) ?? Status::Clean,
                score: (int) ($check['score'] ?? 0),
                reason: (string) ($check['reason'] ?? ''),
                evidence: (array) ($check['evidence'] ?? []),
            );
        }

        return new self($status, (int) ($data['score'] ?? 0), $results);
    }
}
