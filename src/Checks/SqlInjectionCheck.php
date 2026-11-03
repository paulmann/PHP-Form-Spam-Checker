<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;
use FormSpamChecker\Support\Patterns;

/**
 * SQL-injection signatures.
 *
 * Strong patterns are impossible in a normal contact message and produce a
 * hard Spam verdict; weak ones (e.g. "select ... from") only add points,
 * because a technician may legitimately describe a SQL query in a comment.
 */
final class SqlInjectionCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'sql_injection';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('sql_injection.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $text = $submission->text($this->config->excludedFields());

        if ($text === '') {
            return CheckResult::clean($this->name(), 'no text to scan');
        }

        foreach (Patterns::sqlStrongPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return CheckResult::spam(
                    $this->name(),
                    'SQL-injection signature detected',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                    $this->config->int('sql_injection.spam_score', 100),
                );
            }
        }

        foreach (Patterns::sqlWeakPatterns() as $pattern) {
            $result = @preg_match($pattern, $text, $matches);
            if ($result === 1) {
                return CheckResult::suspicious(
                    $this->name(),
                    $this->config->int('sql_injection.suspicious_score', 40),
                    'possible SQL fragment in text',
                    ['pattern' => $pattern, 'match' => mb_substr((string) ($matches[0] ?? ''), 0, 120)],
                );
            }
        }

        return CheckResult::clean($this->name());
    }
}
