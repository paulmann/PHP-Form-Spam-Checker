<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;

/**
 * Honeypot: a field hidden with CSS that a human never sees and never fills.
 *
 * Any non-empty value is conclusive evidence of automation, therefore this
 * check returns a hard Spam verdict (score 100 by default).
 */
final class HoneypotCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'honeypot';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('honeypot.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $filled = [];

        foreach ($this->config->array('honeypot.fields', []) as $field) {
            if (!is_string($field) || $field === '' || !$submission->has($field)) {
                continue;
            }

            $value = $submission->value($field);
            if ($value !== '') {
                $filled[$field] = mb_substr($value, 0, 80);
            }
        }

        if ($filled === []) {
            return CheckResult::clean($this->name(), 'honeypot empty');
        }

        return CheckResult::spam(
            $this->name(),
            sprintf('honeypot field filled: %s', implode(', ', array_keys($filled))),
            ['fields' => $filled],
            $this->config->int('honeypot.score', 100),
        );
    }
}
