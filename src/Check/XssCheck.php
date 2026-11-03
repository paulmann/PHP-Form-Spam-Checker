<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Support\Patterns;

/**
 * XSS signatures: executable markup and JavaScript URIs are hard Spam; encoded
 * variants are only scored because entity-encoded brackets occur in prose.
 */
final readonly class XssCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'xss';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('xss.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $text = $data->text($this->config->excludedFields());

        if ($text === '') {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        foreach (Patterns::xssStrongPatterns() as $pattern) {
            if (@preg_match($pattern, $text, $matches) === 1) {
                return new CheckOutcome(
                    $this->name(),
                    CheckStatus::SPAM,
                    $this->config->int('xss.spam_score', 100),
                    'XSS signature detected',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                );
            }
        }

        foreach (Patterns::xssWeakPatterns() as $pattern) {
            if (@preg_match($pattern, $text, $matches) === 1) {
                return CheckOutcome::suspicious(
                    $this->name(),
                    $this->config->int('xss.suspicious_score', 45),
                    'possible encoded XSS payload',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                );
            }
        }

        return CheckOutcome::ham($this->name());
    }
}
