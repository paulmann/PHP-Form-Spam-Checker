<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

use Psr\SimpleCache\CacheInterface as PsrSimpleCache;

/**
 * PSR-16 cache adapter.
 *
 * `CacheInterface` uses `ttl = 0` for "no explicit TTL / driver default"; PSR-16
 * uses `null` for that and treats `0` as "delete now", so the adapter maps
 * `0` to `null` instead of forwarding it.
 */
final readonly class Psr16CacheAdapter implements CacheInterface
{
    public function __construct(private PsrSimpleCache $cache) {}

    public function get(string $key): mixed
    {
        return $this->cache->get($key);
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
        $this->cache->set($key, $value, $ttl > 0 ? $ttl : null);
    }

    public function has(string $key): bool
    {
        return $this->cache->has($key);
    }

    public function delete(string $key): void
    {
        $this->cache->delete($key);
    }
}
