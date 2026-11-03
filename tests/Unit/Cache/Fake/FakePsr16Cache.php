<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Cache\Fake;

use DateInterval;
use Psr\SimpleCache\CacheInterface as PsrSimpleCache;

/**
 * Recording PSR-16 implementation: keeps values and the TTL each write used.
 */
final class FakePsr16Cache implements PsrSimpleCache
{
    /**
     * @var array<string, mixed>
     */
    public array $values = [];

    /**
     * @var array<string, null|int|DateInterval>
     */
    public array $ttls = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return \array_key_exists($key, $this->values) ? $this->values[$key] : $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->values[$key] = $value;
        $this->ttls[$key] = $ttl;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key], $this->ttls[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];
        $this->ttls = [];

        return true;
    }

    /**
     * @return iterable<string, mixed>
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];

        foreach ($keys as $key) {
            if (\is_string($key)) {
                $values[$key] = $this->get($key, $default);
            }
        }

        return $values;
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            if (\is_string($key)) {
                $this->set($key, $value, $ttl);
            }
        }

        return true;
    }

    /**
     * @param iterable<string> $keys
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            if (\is_string($key)) {
                $this->delete($key);
            }
        }

        return true;
    }

    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->values);
    }
}
