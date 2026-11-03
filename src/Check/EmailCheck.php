<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Support\Patterns;

/**
 * E-mail quality: syntax and disposable domains.
 */
final readonly class EmailCheck implements SpamCheckInterface
{
    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'email';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('email.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $disposable = Patterns::disposableDomains();
        foreach ($this->config->array('email.disposable_domains', []) as $domain) {
            if (\is_string($domain) && $domain !== '') {
                $disposable[] = mb_strtolower($domain);
            }
        }

        $score = 0;
        $reasons = [];
        $findings = [];

        foreach ($this->config->array('email.fields', []) as $field) {
            if (!\is_string($field) || $field === '') {
                continue;
            }

            $value = $data->field($field);
            if ($value === '') {
                continue;
            }

            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                $score += $this->config->int('email.invalid_score', 40);
                $reasons[] = \sprintf('invalid e-mail in field "%s"', $field);
                $findings[] = ['field' => $field, 'reason' => 'invalid'];
                continue;
            }

            $at = strrpos($value, '@');
            if ($at === false) {
                continue;
            }

            $domain = mb_strtolower(substr($value, $at + 1));
            foreach ($disposable as $candidate) {
                if ($domain === $candidate || str_ends_with($domain, '.' . $candidate)) {
                    $score += $this->config->int('email.disposable_score', 70);
                    $reasons[] = \sprintf('disposable e-mail domain "%s" in field "%s"', $domain, $field);
                    $findings[] = ['field' => $field, 'reason' => 'disposable', 'domain' => $domain];
                    break;
                }
            }
        }

        if ($score === 0) {
            return CheckOutcome::ham($this->name(), 'e-mail addresses look valid');
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(100, $score),
            implode('; ', array_unique($reasons)),
            ['findings' => $findings],
        );
    }
}
