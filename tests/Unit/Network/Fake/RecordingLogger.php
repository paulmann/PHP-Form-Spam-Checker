<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network\Fake;

use FormSpamChecker\Log\LoggerInterface;

/**
 * Logger that keeps every record for assertions.
 */
final class RecordingLogger implements LoggerInterface
{
    /**
     * @var list<array{level: string, message: string, context: array<string, mixed>}>
     */
    public array $entries = [];

    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context = []): void
    {
        $this->entries[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }

    /**
     * @param array<string, mixed> $context
     */
    public function error(string $message, array $context = []): void
    {
        $this->log('error', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function info(string $message, array $context = []): void
    {
        $this->log('info', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    public function hasLevel(string $level): bool
    {
        foreach ($this->entries as $entry) {
            if ($entry['level'] === $level) {
                return true;
            }
        }

        return false;
    }
}
