<?php

declare(strict_types=1);

namespace FormSpamChecker\Dns;

use FormSpamChecker\Cache\CacheInterface;

/**
 * Caching decorator for any resolver.
 *
 * Positive and negative answers are cached with a TTL so that a burst of form
 * submissions causes one DNS lookup instead of hundreds.
 */
final readonly class CachedResolver implements ResolverInterface
{
    public function __construct(
        private ResolverInterface $inner,
        private CacheInterface $cache,
        private int $ttl = 3600,
    ) {}

    /**
     * @return list<string>
     */
    public function txt(string $name): array
    {
        return $this->remember('txt', $name);
    }

    /**
     * @return list<string>
     */
    public function a(string $name): array
    {
        return $this->remember('a', $name);
    }

    /**
     * @return list<string>
     */
    public function mx(string $name): array
    {
        return $this->remember('mx', $name);
    }

    /**
     * @return list<string>
     */
    private function remember(string $type, string $name): array
    {
        $key = 'dns:' . $type . ':' . strtolower(rtrim($name, '.'));

        $cached = $this->cache->get($key);
        if (\is_array($cached)) {
            return array_values(array_filter($cached, static fn(mixed $value): bool => \is_string($value)));
        }

        $records = match ($type) {
            'txt' => $this->inner->txt($name),
            'a' => $this->inner->a($name),
            'mx' => $this->inner->mx($name),
            default => [],
        };

        $this->cache->set($key, $records, $this->ttl);

        return $records;
    }
}
