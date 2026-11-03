<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Exception\InvalidConfigException;
use FormSpamChecker\Token\FormToken;

/**
 * Signed time trap: a token records when the form was rendered.
 *
 * A submission that arrives milliseconds after render is automated; a token
 * that does not verify was not issued by this server. A missing token is only
 * suspicious, because cached pages may legitimately miss it.
 */
final readonly class TimeTrapCheck implements SpamCheckInterface
{
    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'time_trap';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('time_trap.enabled', false)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $field = $this->config->string('time_trap.field', '_fs_ts');
        $token = $data->field($field);

        if ($token === '') {
            if (!$this->config->bool('time_trap.require_token', true)) {
                return CheckOutcome::ham($this->name(), 'token not required');
            }

            return CheckOutcome::suspicious(
                $this->name(),
                $this->config->int('time_trap.suspicious_score', 30),
                'time token missing',
                ['field' => $field],
            );
        }

        try {
            $formToken = new FormToken($this->config->secret());
        } catch (InvalidConfigException $exception) {
            return CheckOutcome::error($this->name(), 'time trap misconfigured: ' . $exception->getMessage());
        }

        $issuedAt = $formToken->verify($token, $data->formId);

        if ($issuedAt === null) {
            return new CheckOutcome(
                $this->name(),
                CheckStatus::SPAM,
                $this->config->int('time_trap.spam_score', 80),
                'forged or corrupted time token',
                ['field' => $field],
            );
        }

        $age = $data->timestamp() - $issuedAt;

        if ($age < 0) {
            return new CheckOutcome(
                $this->name(),
                CheckStatus::SPAM,
                $this->config->int('time_trap.spam_score', 80),
                'time token issued in the future',
                ['age' => $age],
            );
        }

        $minSeconds = $this->config->int('time_trap.min_seconds', 2);
        if ($age < $minSeconds) {
            return new CheckOutcome(
                $this->name(),
                CheckStatus::SPAM,
                $this->config->int('time_trap.spam_score', 80),
                \sprintf('form submitted after %d s, minimum is %d s', $age, $minSeconds),
                ['age' => $age, 'min' => $minSeconds],
            );
        }

        $maxSeconds = $this->config->int('time_trap.max_seconds', 604800);
        if ($age > $maxSeconds) {
            return CheckOutcome::suspicious(
                $this->name(),
                $this->config->int('time_trap.suspicious_score', 30),
                \sprintf('time token is %d s old (max %d s), page was probably cached', $age, $maxSeconds),
                ['age' => $age, 'max' => $maxSeconds],
            );
        }

        return CheckOutcome::ham($this->name(), \sprintf('submitted %d s after render', $age));
    }
}
