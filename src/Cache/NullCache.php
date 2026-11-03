<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

/**
 * Null cache: used when remote checks are disabled or in "no cache" tests.
 */
final readonly class NullCache implements CacheInterface
{
    public function get(string $key): mixed
    {
        return null;
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
    }

    public function has(string $key): bool
    {
        return false;
    }

    public function delete(string $key): void
    {
    }
}
