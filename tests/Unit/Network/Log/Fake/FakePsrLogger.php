<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network\Log\Fake;

use Psr\Log\LoggerInterface;
use Stringable;

/**
 * Recording PSR-3 logger for the adapter test.
 */
final class FakePsrLogger implements LoggerInterface
{
    /**
     * @var list<array{level: string, message: string, context: array<string, mixed>}>
     */
    public array $entries = [];

    public function emergency(string|Stringable $message, array $context = []): void
    {
        $this->record('emergency', $message, $context);
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
        $this->record('alert', $message, $context);
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
        $this->record('critical', $message, $context);
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        $this->record('error', $message, $context);
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->record('warning', $message, $context);
    }

    public function notice(string|Stringable $message, array $context = []): void
    {
        $this->record('notice', $message, $context);
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        $this->record('info', $message, $context);
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        $this->record('debug', $message, $context);
    }

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->record(\is_string($level) ? $level : 'unknown', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function record(string $level, string|Stringable $message, array $context): void
    {
        $this->entries[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
    }
}
