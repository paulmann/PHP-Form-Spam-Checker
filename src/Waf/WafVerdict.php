<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

/**
 * Aggregated result of a WAF inspection.
 *
 * The verdict has no opinion about modes: whether a blocked request is
 * answered with 403 or only written to the log is the guard's decision (see
 * `WafGuard`). That keeps the WAF usable from a library and from a synchronous
 * auto-prepend alike.
 */
final readonly class WafVerdict
{
    public const string STATUS_CLEAN = 'clean';
    public const string STATUS_SUSPICIOUS = 'suspicious';
    public const string STATUS_BLOCKED = 'blocked';

    /** @var list<string> */
    public const array STATUSES = [self::STATUS_CLEAN, self::STATUS_SUSPICIOUS, self::STATUS_BLOCKED];

    /**
     * @param list<WafFinding> $findings
     */
    public function __construct(
        public bool $blocked,
        public int $score,
        public array $findings,
        public string $status,
    ) {
        if ($score < 0 || $score > 100) {
            throw new \InvalidArgumentException(sprintf('WAF score must be between 0 and 100, %d given.', $score));
        }

        if (!in_array($status, self::STATUSES, true)) {
            throw new \InvalidArgumentException(sprintf('Unknown WAF verdict status "%s".', $status));
        }
    }

    public static function clean(): self
    {
        return new self(false, 0, [], self::STATUS_CLEAN);
    }

    public function isBlocked(): bool
    {
        return $this->blocked;
    }

    public function isSuspicious(): bool
    {
        return $this->status === self::STATUS_SUSPICIOUS;
    }

    public function isClean(): bool
    {
        return $this->status === self::STATUS_CLEAN;
    }

    /**
     * Human-readable one-line reasons, one per finding ("rule: reason").
     *
     * @return list<string>
     */
    public function reasons(): array
    {
        $reasons = [];

        foreach ($this->findings as $finding) {
            $reasons[] = $finding->reason !== ''
                ? $finding->rule . ': ' . $finding->reason
                : $finding->rule;
        }

        return array_values(array_unique($reasons));
    }

    /**
     * @return list<string>
     */
    public function ruleNames(): array
    {
        $names = [];

        foreach ($this->findings as $finding) {
            $names[] = $finding->rule;
        }

        return array_values(array_unique($names));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'blocked' => $this->blocked,
            'status' => $this->status,
            'score' => $this->score,
            'reasons' => $this->reasons(),
            'findings' => array_map(
                static fn (WafFinding $finding): array => $finding->toArray(),
                $this->findings,
            ),
        ];
    }
}
