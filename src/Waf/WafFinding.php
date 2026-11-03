<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

/**
 * One rule result: what was found, how bad it is and where.
 *
 * `hard` is the difference between "block the request" and "add suspicion
 * points"; it is a rule decision, not a threshold decision. The WAF aggregates
 * findings: any hard one blocks, soft ones accumulate up to 100.
 */
final readonly class WafFinding
{
    /**
     * @param int                  $severity 0..100; contributes to the score
     * @param array<string, mixed> $evidence
     * @param string               $location where the match was found
     *                                       (`query.name`, `field.name`,
     *                                       `header.user-agent`, `uri`, `ip`, ...)
     */
    public function __construct(
        public string $rule,
        public int $severity,
        public bool $hard,
        public string $reason,
        public array $evidence = [],
        public string $location = '',
    ) {
        if ($severity < 0 || $severity > 100) {
            throw new \InvalidArgumentException(sprintf(
                'WAF finding severity must be between 0 and 100, %d given for rule "%s".',
                $severity,
                $rule,
            ));
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule' => $this->rule,
            'severity' => $this->severity,
            'hard' => $this->hard,
            'reason' => $this->reason,
            'location' => $this->location,
            'evidence' => $this->evidence,
        ];
    }
}
