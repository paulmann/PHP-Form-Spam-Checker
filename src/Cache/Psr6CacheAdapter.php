<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

use Psr\Cache\CacheItemPoolInterface;

/**
 * PSR-6 cache pool adapter.
 *
 * PSR-6 reserves the characters `{}()/\@:` in keys, while this library uses
 * readable names such as `abuseipdb:203.0.113.5`. Keys are therefore hashed into
 * a safe, bounded (`fsc_` + 48 hex chars) PSR-6 key, deterministically, so the
 * same logical key always maps to the same pool item.
 *
 * `CacheInterface` uses `ttl = 0` for "no explicit TTL"; PSR-6 maps that to
 * `expiresAfter(null)` (no expiration).
 */
final readonly class Psr6CacheAdapter implements CacheInterface
{
    public function __construct(private CacheItemPoolInterface $pool) {}

    public function get(string $key): mixed
    {
        $item = $this->pool->getItem($this->normalizeKey($key));

        return $item->isHit() ? $item->get() : null;
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
        $item = $this->pool->getItem($this->normalizeKey($key));
        $item->set($value);

        $this->pool->save($item->expiresAfter($ttl > 0 ? $ttl : null));
    }

    public function has(string $key): bool
    {
        return $this->pool->hasItem($this->normalizeKey($key));
    }

    public function delete(string $key): void
    {
        $this->pool->deleteItem($this->normalizeKey($key));
    }

    private function normalizeKey(string $key): string
    {
        return 'fsc_' . substr(hash('sha256', $key), 0, 48);
    }
}
