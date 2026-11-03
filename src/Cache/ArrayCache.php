<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

/**
 * Process-local array cache, for tests and single-request CLI runs.
 */
final class ArrayCache implements CacheInterface
{
    /**
     * @var array<string, array{value: mixed, expires: int}>
     */
    private array $entries = [];

    public function __construct(private int $now = 0)
    {
        if ($this->now === 0) {
            $this->now = time();
        }
    }

    public function get(string $key): mixed
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null) {
            return null;
        }

        if ($entry['expires'] !== 0 && $entry['expires'] <= $this->now) {
            unset($this->entries[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
        $this->entries[$key] = [
            'value' => $value,
            'expires' => $ttl > 0 ? $this->now + $ttl : 0,
        ];
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function delete(string $key): void
    {
        unset($this->entries[$key]);
    }

    /**
     * Advance the internal clock without sleeping (tests).
     */
    public function travel(int $seconds): void
    {
        $this->now += $seconds;
    }
}
