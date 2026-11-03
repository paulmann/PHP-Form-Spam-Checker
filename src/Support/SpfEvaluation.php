<?php

declare(strict_types=1);

namespace FormSpamChecker\Support;

/**
 * Immutable result of evaluating one domain's SPF policy for one client address.
 *
 * The value object carries everything a check or a log line needs: the result
 * vocabulary value, how many DNS-querying terms were consumed (RFC 7208 §4.6.4
 * limits them to 10), the raw record that was used and a human-readable reason.
 */
final readonly class SpfEvaluation
{
    public function __construct(
        public string $domain,
        public SpfResult $result,
        public string $reason = '',
        public int $lookups = 0,
        public string $record = '',
    ) {}

    public function isPass(): bool
    {
        return $this->result === SpfResult::PASS;
    }

    public function isFail(): bool
    {
        return $this->result === SpfResult::FAIL;
    }

    public function isSoftFail(): bool
    {
        return $this->result === SpfResult::SOFTFAIL;
    }

    public function isNeutral(): bool
    {
        return $this->result === SpfResult::NEUTRAL;
    }

    /**
     * No SPF record published for the domain.
     */
    public function isNone(): bool
    {
        return $this->result === SpfResult::NONE;
    }

    /**
     * The policy is syntactically invalid or exceeds the lookup limit.
     */
    public function isPermError(): bool
    {
        return $this->result === SpfResult::PERMERROR;
    }

    public function isTempError(): bool
    {
        return $this->result === SpfResult::TEMPERROR;
    }
}
