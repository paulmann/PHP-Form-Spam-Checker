<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;
use FormSpamChecker\Support\Patterns;

/**
 * E-mail quality: syntax and disposable domains.
 *
 * A syntactically broken address is suspicious (the form validator normally
 * catches it first, and a bypassed validator is itself a signal). A throwaway
 * mailbox is a much stronger signal and adds enough points to cross the spam
 * threshold on its own by default.
 */
final class EmailCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'email';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('email.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $fields = $this->config->array('email.fields', []);
        $disposable = Patterns::disposableDomains();

        foreach ($this->config->array('email.disposable_domains', []) as $domain) {
            if (is_string($domain) && $domain !== '') {
                $disposable[] = mb_strtolower($domain);
            }
        }

        $score = 0;
        $reasons = [];
        $evidence = [];

        foreach ($fields as $field) {
            if (!is_string($field) || $field === '') {
                continue;
            }

            $value = $submission->value($field);
            if ($value === '') {
                continue;
            }

            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                $score += $this->config->int('email.invalid_score', 40);
                $reasons[] = sprintf('invalid e-mail in field "%s"', $field);
                $evidence[] = ['field' => $field, 'reason' => 'invalid'];
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
                    $reasons[] = sprintf('disposable e-mail domain "%s" in field "%s"', $domain, $field);
                    $evidence[] = ['field' => $field, 'reason' => 'disposable', 'domain' => $domain];
                    break;
                }
            }
        }

        if ($score === 0) {
            return CheckResult::clean($this->name(), 'e-mail addresses look valid');
        }

        return CheckResult::suspicious(
            $this->name(),
            min(100, $score),
            implode('; ', array_unique($reasons)),
            ['findings' => $evidence],
        );
    }
}
