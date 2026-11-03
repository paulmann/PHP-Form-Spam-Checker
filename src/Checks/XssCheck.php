<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;
use FormSpamChecker\Support\Patterns;

/**
 * Cross-site-scripting signatures.
 *
 * A form field that contains a script tag or a JavaScript URI is an attack,
 * not a message: strong patterns are a hard Spam verdict. Encoded variants are
 * only suspicious, since entity-encoded angle brackets appear in legitimate
 * HTML-heavy correspondence.
 */
final class XssCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'xss';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('xss.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $text = $submission->text($this->config->excludedFields());

        if ($text === '') {
            return CheckResult::clean($this->name(), 'no text to scan');
        }

        foreach (Patterns::xssStrongPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return CheckResult::spam(
                    $this->name(),
                    'XSS signature detected',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                    $this->config->int('xss.spam_score', 100),
                );
            }
        }

        foreach (Patterns::xssWeakPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return CheckResult::suspicious(
                    $this->name(),
                    $this->config->int('xss.suspicious_score', 45),
                    'possible encoded XSS payload',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                );
            }
        }

        return CheckResult::clean($this->name());
    }
}
