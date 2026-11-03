<?php

declare(strict_types=1);

namespace FormSpamChecker\Log;

/**
 * Fallback logger writing to the PHP error log.
 *
 * Used when the application does not inject a PSR-3 logger. Message placeholders
 * are interpolated PSR-3 style, values are stringified safely.
 */
final readonly class ErrorLogLogger implements LoggerInterface
{
    private const string PREFIX = '[php-form-spam-checker]';

    public function __construct(private string $channel = 'default')
    {
    }

    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $message, array $context = []): void
    {
        $line = sprintf(
            '%s %s.%s: %s',
            self::PREFIX,
            $this->channel,
            strtoupper($level),
            $this->interpolate($message, $context),
        );

        error_log($line);
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

    /**
     * @param array<string, mixed> $context
     */
    private function interpolate(string $message, array $context): string
    {
        $replace = [];
        foreach ($context as $key => $value) {
            if (!is_scalar($value) && !$value instanceof \Stringable) {
                $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?: '';
            }
            $replace['{' . $key . '}'] = (string) $value;
        }

        return strtr($message, $replace);
    }
}
