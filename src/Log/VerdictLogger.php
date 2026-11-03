<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;

/**
 * Appends one JSON line per verdict to a file.
 *
 * PII (IP, User-Agent, field samples) is stored only when `pii` is enabled; by
 * default the IP is pseudonymised and the fields are redacted.
 */
final readonly class VerdictLogger
{
    /**
     * @param list<string> $excludedFields fields never stored even in PII mode
     */
    public function __construct(
        private string $path,
        private bool $pii = false,
        private bool $sampleFields = true,
        private array $excludedFields = [],
    ) {
    }

    public function path(): string
    {
        return $this->path;
    }

    public function log(Verdict $verdict, RequestData $request): void
    {
        $record = [
            'ts' => gmdate('Y-m-d\TH:i:s\Z'),
            'form' => $request->formId,
            'status' => $verdict->status->value,
            'score' => $verdict->score,
            'reasons' => $verdict->reasons(),
            'ip' => $this->ip($request->ip),
            'page' => mb_substr($request->uri, 0, 200),
            'checks' => array_map(
                static fn ($outcome): array => $outcome->toArray(),
                $verdict->outcomes,
            ),
            'fields' => $this->fields($request),
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

        return substr(hash('sha256', 'php-form-spam-checker|' . $ip), 0, 16);
    }

    /**
     * @return array<string, string>|string
     */
    private function fields(RequestData $request): array|string
    {
        if (!$this->pii || !$this->sampleFields) {
            return 'redacted';
        }

        return $request->sample($this->excludedFields);
    }
}
