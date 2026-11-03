<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

use Psr\Log\LoggerInterface as PsrLogger;

/**
 * PSR-3 logger adapter: forwards the library's small logging surface to the
 * application logger.
 *
 * The library only calls the levels it needs (`error`, `warning`, `info`,
 * `debug`, plus the generic `log`), so `emergency`/`alert`/`critical`/`notice`
 * are not part of `LoggerInterface` and are never emitted.
 */
final readonly class Psr3LoggerAdapter implements LoggerInterface
{
    public function __construct(private PsrLogger $logger) {}

    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context = []): void
    {
        $this->logger->log($level, $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function error(string $message, array $context = []): void
    {
        $this->logger->error($message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function warning(string $message, array $context = []): void
    {
        $this->logger->warning($message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function info(string $message, array $context = []): void
    {
        $this->logger->info($message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function debug(string $message, array $context = []): void
    {
        $this->logger->debug($message, $context);
    }
}
