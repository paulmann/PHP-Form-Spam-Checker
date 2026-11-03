<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

/**
 * Simple key/value cache with TTL (PSR-16 shaped).
 *
 * Values are plain PHP data (scalars, arrays) serialised by the adapter. A
 * missing or expired key returns null. A TTL of 0 (the default) means "no
 * automatic expiry", which is used for long-lived entries such as the Bayesian
 * model; remote-response caches always pass an explicit TTL.
 */
interface CacheInterface
{
    public function get(string $key): mixed;

    /**
     * Store a value. `$ttl <= 0` disables automatic expiry.
     */
    public function set(string $key, mixed $value, int $ttl = 0): void;

    public function has(string $key): bool;

    public function delete(string $key): void;
}
