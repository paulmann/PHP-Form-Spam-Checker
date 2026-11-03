<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Support\Patterns;

/**
 * SQL-injection signatures: strong patterns are hard Spam, weak fragments are
 * only scored.
 */
final readonly class SqlInjectionCheck implements SpamCheckInterface
{
    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'sql_injection';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('sql_injection.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $text = $data->text($this->config->excludedFields());

        if ($text === '') {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        foreach (Patterns::sqlStrongPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return new CheckOutcome(
                    $this->name(),
                    CheckStatus::SPAM,
                    $this->config->int('sql_injection.spam_score', 100),
                    'SQL-injection signature detected',
                    ['pattern' => $pattern, 'match' => mb_substr($matches[0] ?? '', 0, 120)],
                );
            }
        }

        foreach (Patterns::sqlWeakPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return CheckOutcome::suspicious(
                    $this->name(),
                    $this->config->int('sql_injection.suspicious_score', 40),
                    'possible SQL fragment in text',
                    ['pattern' => $pattern, 'match' => mb_substr($matches[0] ?? '', 0, 120)],
                );
            }
        }

        return CheckOutcome::ham($this->name());
    }
}
