<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

/**
 * Simple key/value cache with TTL (PSR-16 shaped).
 *
 * Values are plain PHP data (scalars, arrays) serialised by the adapter. A
 * missing or expired key returns null.
 */
interface CacheInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttl = 0): void;

    public function has(string $key): bool;

    public function delete(string $key): void;
}
