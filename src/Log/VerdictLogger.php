<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

use FormSpamChecker\Submission;
use FormSpamChecker\Verdict;

/**
 * Appends one JSON line per verdict to a file.
 *
 * Useful on hosts without a log aggregation stack: `tail -f` answers "what is
 * being blocked right now" and `jq` gives per-check statistics. PII (IP, User
 * Agent, field samples) is stored only when `pii` is enabled; by default the IP
 * is hashed and the fields are redacted.
 */
final class VerdictLogger
{
    public function __construct(
        private readonly string $path,
        private readonly bool $pii = false,
        private readonly bool $sampleFields = true,
    ) {
    }

    public function path(): string
    {
        return $this->path;
    }

    public function log(Verdict $verdict, Submission $submission): void
    {
        $record = [
            'ts' => gmdate('Y-m-d\TH:i:s\Z'),
            'form' => $submission->formId,
            'status' => $verdict->status->value,
            'score' => $verdict->score,
            'reasons' => $verdict->reasons(),
            'ip' => $this->ip($submission->context->ip),
            'page' => mb_substr($submission->context->page, 0, 200),
            'checks' => array_map(
                static fn ($result): array => $result->toArray(),
                $verdict->results,
            ),
            'fields' => $this->fields($submission),
        ];

        $this->append($record);
    }

    /**
     * @param array<string, mixed> $record
     */
    private function append(array $record): void
    {
        $directory = dirname($this->path);

        if (!is_dir($directory) && !@mkdir($directory, 0775, true) && !is_dir($directory)) {
            return;
        }

        $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";

        @file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX);
    }

    private function ip(string $ip): ?string
    {
        if ($ip === '') {
            return null;
        }

        if ($this->pii) {
            return $ip;
        }

        // Stable per-installation pseudonym: enough to correlate abuse across
        // submissions, not enough to recover the address.
        return substr(hash('sha256', 'php-form-spam-checker|' . $ip), 0, 16);
    }

    /**
     * @return array<string, string>|string
     */
    private function fields(Submission $submission): array|string
    {
        if (!$this->pii || !$this->sampleFields) {
            return 'redacted';
        }

        return $submission->sample();
    }
}
