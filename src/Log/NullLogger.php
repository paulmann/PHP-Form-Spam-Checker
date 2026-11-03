<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

/**
 * Logger that discards everything; useful in tests and CLI dry runs.
 */
final readonly class NullLogger implements LoggerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context = []): void {}

    /**
     * @param array<string, mixed> $context
     */
    public function error(string $message, array $context = []): void {}

    /**
     * @param array<string, mixed> $context
     */
    public function warning(string $message, array $context = []): void {}

    /**
     * @param array<string, mixed> $context
     */
    public function info(string $message, array $context = []): void {}

    /**
     * @param array<string, mixed> $context
     */
    public function debug(string $message, array $context = []): void {}
}
