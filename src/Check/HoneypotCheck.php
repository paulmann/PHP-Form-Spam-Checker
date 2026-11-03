<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;

/**
 * Static honeypot: fields hidden with CSS that a human never fills.
 *
 * Any non-empty value is conclusive evidence of automation, therefore a hard
 * Spam verdict. The dynamic variant lives in DynamicHoneypotCheck.
 */
final readonly class HoneypotCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'honeypot';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('honeypot.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $filled = [];
        foreach ($this->config->array('honeypot.fields', []) as $field) {
            if (!is_string($field) || $field === '' || !$data->hasField($field)) {
                continue;
            }

            $value = $data->field($field);
            if ($value !== '') {
                $filled[$field] = mb_substr($value, 0, 80);
            }
        }

        if ($filled === []) {
            return CheckOutcome::ham($this->name(), 'honeypot empty');
        }

        return new CheckOutcome(
            $this->name(),
            CheckStatus::SPAM,
            $this->config->int('honeypot.score', 100),
            sprintf('honeypot field filled: %s', implode(', ', array_keys($filled))),
            ['fields' => $filled],
        );
    }
}
