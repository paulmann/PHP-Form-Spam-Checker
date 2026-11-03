<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * Request context that is not part of the submitted fields.
 *
 * Everything here is untrusted input: the checker only uses it as a signal and
 * never interpolates it into SQL, shell commands or HTML.
 */
final class Context
{
    public function __construct(
        public readonly string $ip = '',
        public readonly string $userAgent = '',
        public readonly string $referer = '',
        public readonly string $page = '',
        public readonly ?int $now = null,
    ) {
    }

    public function timestamp(): int
    {
        return $this->now ?? time();
    }

    /**
     * Build the context from the current request superglobals.
     */
    public static function fromGlobals(): self
    {
        return self::fromServer($_SERVER);
    }

    /**
     * Build the context from an explicit server array.
     *
     * @param array<string, mixed> $server
     */
    public static function fromServer(array $server): self
    {
        $ip = '';
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
            if (isset($server[$key]) && is_string($server[$key]) && trim($server[$key]) !== '') {
                $ip = trim($server[$key]);
                break;
            }
        }

        // X-Forwarded-For: the left-most address is the client, but only trust it
        // when the connecting peer is a local reverse proxy.
        if (isset($server['HTTP_X_FORWARDED_FOR']) && is_string($server['HTTP_X_FORWARDED_FOR'])) {
            $remote = (string) ($server['REMOTE_ADDR'] ?? '');
            if (self::isLoopback($remote)) {
                $first = trim(explode(',', $server['HTTP_X_FORWARDED_FOR'])[0]);
                if (filter_var($first, FILTER_VALIDATE_IP) !== false) {
                    $ip = $first;
                }
            }
        }

        return new self(
            ip: $ip,
            userAgent: isset($server['HTTP_USER_AGENT']) && is_string($server['HTTP_USER_AGENT'])
                ? mb_substr($server['HTTP_USER_AGENT'], 0, 512)
                : '',
            referer: isset($server['HTTP_REFERER']) && is_string($server['HTTP_REFERER'])
                ? mb_substr($server['HTTP_REFERER'], 0, 1024)
                : '',
            page: isset($server['REQUEST_URI']) && is_string($server['REQUEST_URI'])
                ? mb_substr($server['REQUEST_URI'], 0, 512)
                : '',
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $now = $data['now'] ?? null;

        return new self(
            ip: self::str($data, 'ip'),
            userAgent: self::str($data, 'userAgent', 'user_agent', 'ua'),
            referer: self::str($data, 'referer'),
            page: self::str($data, 'page'),
            now: is_int($now) || (is_string($now) && ctype_digit($now)) ? (int) $now : null,
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function str(array $data, string ...$keys): string
    {
        foreach ($keys as $key) {
            if (isset($data[$key]) && is_string($data[$key])) {
                return $data[$key];
            }
        }

        return '';
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'userAgent' => $this->userAgent,
            'referer' => $this->referer,
            'page' => $this->page,
            'now' => $this->timestamp(),
        ];
    }

    private static function isLoopback(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        return $ip === '::1'
            || str_starts_with($ip, '127.')
            || str_starts_with($ip, '::ffff:127.');
    }
}
