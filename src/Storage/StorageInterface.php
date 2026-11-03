<?php

declare(strict_types=1);

namespace FormSpamChecker\Storage;

/**
 * Key/value counter storage used by stateful checks (rate limiting).
 *
 * Implementations must be safe under concurrent requests: two simultaneous
 * submissions from the same IP must never read the same counter value twice.
 * A missing key is not an error; callers decide what an absent value means.
 */
interface StorageInterface
{
    /**
     * Atomically increment a counter and return the new value.
     *
     * If the key does not exist or has expired, the counter starts at 1 and
     * gets a fresh TTL.
     */
    public function increment(string $key, int $ttl): int;

    /**
     * Store a string value with a TTL in seconds.
     */
    public function set(string $key, string $value, int $ttl): void;

    public function get(string $key): ?string;

    public function delete(string $key): void;

    /**
     * Remove expired entries. Implementations may also do this opportunistically.
     */
    public function gc(): void;
}
