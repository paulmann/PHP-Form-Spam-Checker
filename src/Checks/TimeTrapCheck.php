<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Exception\InvalidConfigException;
use FormSpamChecker\Submission;
use FormSpamChecker\Token\FormToken;

/**
 * Signed time trap: a bot submitting a form milliseconds after receiving it is
 * not reading anything, and a token with an invalid signature was not issued
 * by this server at all.
 *
 * The token is HMAC-signed and bound to the form id, so it cannot be forged or
 * replayed across forms. A missing token is only suspicious when the form is
 * configured with `require_token` (default), because old cached pages may still
 * be served without the field.
 */
final class TimeTrapCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'time_trap';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('time_trap.enabled', false)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $field = $this->config->string('time_trap.field', '_fs_ts');
        $token = $submission->value($field);

        if ($token === '') {
            if (!$this->config->bool('time_trap.require_token', true)) {
                return CheckResult::clean($this->name(), 'token not required');
            }

            return CheckResult::suspicious(
                $this->name(),
                $this->config->int('time_trap.suspicious_score', 30),
                'time token missing',
                ['field' => $field],
            );
        }

        try {
            $formToken = new FormToken($this->config->secret());
        } catch (InvalidConfigException $exception) {
            return CheckResult::clean($this->name(), 'time trap misconfigured: ' . $exception->getMessage());
        }

        $issuedAt = $formToken->verify($token, $submission->formId);

        if ($issuedAt === null) {
            return CheckResult::spam(
                $this->name(),
                'forged or corrupted time token',
                ['field' => $field],
                $this->config->int('time_trap.spam_score', 80),
            );
        }

        $age = $submission->context->timestamp() - $issuedAt;

        if ($age < 0) {
            return CheckResult::spam(
                $this->name(),
                'time token issued in the future',
                ['age' => $age],
                $this->config->int('time_trap.spam_score', 80),
            );
        }

        $minSeconds = $this->config->int('time_trap.min_seconds', 2);
        if ($age < $minSeconds) {
            return CheckResult::spam(
                $this->name(),
                sprintf('form submitted after %d s, minimum is %d s', $age, $minSeconds),
                ['age' => $age, 'min' => $minSeconds],
                $this->config->int('time_trap.spam_score', 80),
            );
        }

        $maxSeconds = $this->config->int('time_trap.max_seconds', 604800);
        if ($age > $maxSeconds) {
            return CheckResult::suspicious(
                $this->name(),
                $this->config->int('time_trap.suspicious_score', 30),
                sprintf('time token is %d s old (max %d s), page was probably cached', $age, $maxSeconds),
                ['age' => $age, 'max' => $maxSeconds],
            );
        }

        return CheckResult::clean($this->name(), sprintf('submitted %d s after render', $age));
    }
}
