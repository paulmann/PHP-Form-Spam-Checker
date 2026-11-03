<?php

declare(strict_types=1);

namespace FormSpamChecker\Storage;

use FormSpamChecker\Exception\StorageException;

/**
 * File-backed storage with advisory locking and atomic in-place counters.
 *
 * Why files: a form handler must work on shared hosting and on servers where
 * no Redis, APCu or writable database is available. Every entry is a small
 * JSON file named after a SHA-256 of the key; increment happens under an
 * exclusive lock on that file, so concurrent PHP-FPM workers cannot lose
 * updates.
 */
final class FileStorage implements StorageInterface
{
    private readonly string $directory;

    /**
     * Probability (percent) of running a garbage-collection sweep per write.
     */
    private readonly int $gcPercent;

    public function __construct(string $directory, int $gcPercent = 2)
    {
        $this->directory = rtrim($directory, '/\\');
        $this->gcPercent = max(0, min(100, $gcPercent));

        if (!is_dir($this->directory) && !@mkdir($this->directory, 0775, true) && !is_dir($this->directory)) {
            throw new StorageException(sprintf('Cannot create storage directory: %s', $this->directory));
        }

        if (!is_writable($this->directory)) {
            throw new StorageException(sprintf('Storage directory is not writable: %s', $this->directory));
        }
    }

    public function increment(string $key, int $ttl): int
    {
        return $this->lockedUpdate($key, $ttl, static function (?int $count): array {
            return [($count ?? 0) + 1, null];
        });
    }

    public function set(string $key, string $value, int $ttl): void
    {
        $this->lockedUpdate($key, $ttl, static fn (): array => [null, $value]);
    }

    public function get(string $key): ?string
    {
        $file = $this->path($key);

        if (!is_file($file)) {
            return null;
        }

        $handle = @fopen($file, 'rb');
        if ($handle === false) {
            return null;
        }

        try {
            if (!flock($handle, LOCK_SH)) {
                return null;
            }
            $raw = stream_get_contents($handle);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }

        $entry = $this->decode($raw === false ? '' : $raw);

        if ($entry === null || $entry['expires'] <= time()) {
            return null;
        }

        return $entry['value'];
    }

    public function delete(string $key): void
    {
        $file = $this->path($key);
        if (is_file($file)) {
            @unlink($file);
        }
    }

    public function gc(): void
    {
        $now = time();
        $files = glob($this->directory . DIRECTORY_SEPARATOR . '*.json');

        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            $raw = @file_get_contents($file);
            if ($raw === false) {
                continue;
            }

            $entry = $this->decode($raw);
            if ($entry === null || $entry['expires'] <= $now) {
                @unlink($file);
            }
        }
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
    }

    /**
     * @param callable(?int): array{0: int|null, 1: string|null} $mutator
     */
    private function lockedUpdate(string $key, int $ttl, callable $mutator): int
    {
        $file = $this->path($key);
        $handle = @fopen($file, 'c+b');

        if ($handle === false) {
            throw new StorageException(sprintf('Cannot open storage entry for writing: %s', $file));
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new StorageException(sprintf('Cannot lock storage entry: %s', $file));
            }

            $raw = stream_get_contents($handle);
            $existing = $this->decode($raw === false ? '' : $raw);
            $current = $existing !== null && $existing['expires'] > time() ? (int) $existing['value'] : null;

            [$count, $value] = $mutator($current);

            $payload = json_encode([
                'value' => $value ?? (string) $count,
                'expires' => time() + max(1, $ttl),
            ], JSON_THROW_ON_ERROR);

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, $payload);
            fflush($handle);
            flock($handle, LOCK_UN);

            if ($this->gcPercent > 0 && random_int(1, 100) <= $this->gcPercent) {
                $this->gc();
            }

            return $count ?? (int) ($value ?? 0);
        } finally {
            if (is_resource($handle)) {
                fclose($handle);
            }
        }
    }

    /**
     * @return array{value: string, expires: int}|null
     */
    private function decode(string $raw): ?array
    {
        if ($raw === '') {
            return null;
        }

        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (!is_array($data) || !isset($data['value'], $data['expires']) || !is_int($data['expires'])) {
            return null;
        }

        return ['value' => (string) $data['value'], 'expires' => $data['expires']];
    }
}
