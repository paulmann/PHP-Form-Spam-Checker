<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

/**
 * PSR-3-shaped logger abstraction.
 *
 * Deliberately small: the library only needs the levels it actually uses, and
 * a PSR-3 adapter is provided for applications that already have a logger.
 */
interface LoggerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context = []): void;

    /**
     * @param array<string, mixed> $context
     */
    public function error(string $message, array $context = []): void;

    /**
     * @param array<string, mixed> $context
     */
    public function warning(string $message, array $context = []): void;

    /**
     * @param array<string, mixed> $context
     */
    public function info(string $message, array $context = []): void;

    /**
     * @param array<string, mixed> $context
     */
    public function debug(string $message, array $context = []): void;
}
