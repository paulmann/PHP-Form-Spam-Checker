<?php

declare(strict_types=1);

namespace FormSpamChecker\Storage;

/**
 * Array-backed storage for tests and single-request CLI runs.
 *
 * It is intentionally NOT shared between processes: for production form
 * handling use FileStorage (or a custom StorageInterface backed by Redis).
 */
final class MemoryStorage implements StorageInterface
{
    /**
     * @var array<string, array{value: string, expires: int}>
     */
    private array $entries = [];

    private int $now;

    public function __construct(?int $now = null)
    {
        $this->now = $now ?? time();
    }

    public function increment(string $key, int $ttl): int
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null || $entry['expires'] <= $this->now) {
            $this->entries[$key] = ['value' => '1', 'expires' => $this->now + $ttl];

            return 1;
        }

        $count = (int) $entry['value'] + 1;
        $this->entries[$key] = ['value' => (string) $count, 'expires' => $entry['expires']];

        return $count;
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $this->entries[$key] = ['value' => $value, 'expires' => $this->now + $ttl];
    }

    public function get(string $key): ?string
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null || $entry['expires'] <= $this->now) {
            unset($this->entries[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function delete(string $key): void
    {
        unset($this->entries[$key]);
    }

    public function gc(): void
    {
        foreach ($this->entries as $key => $entry) {
            if ($entry['expires'] <= $this->now) {
                unset($this->entries[$key]);
            }
        }
    }

    /**
     * Advance the internal clock; keeps TTL behaviour testable without sleeping.
     */
    public function travel(int $seconds): void
    {
        $this->now += $seconds;
    }
}
