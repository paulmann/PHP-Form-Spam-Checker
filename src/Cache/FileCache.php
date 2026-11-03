<?php

declare(strict_types=1);

namespace FormSpamChecker\Cache;

use FormSpamChecker\Exception\StorageException;

/**
 * File-backed cache for hosts without Redis/APCu.
 *
 * One JSON file per hashed key, atomic replace via temporary file + rename.
 * Values must be JSON-serialisable; anything else is stored as a string.
 */
final readonly class FileCache implements CacheInterface
{
    private string $directory;

    public function __construct(string $directory, private int $gcPercent = 2)
    {
        $this->directory = rtrim($directory, '/\\');

        if (!is_dir($this->directory) && !@mkdir($this->directory, 0775, true) && !is_dir($this->directory)) {
            throw new StorageException('Cannot create cache directory: ' . $this->directory);
        }

        if (!is_writable($this->directory)) {
            throw new StorageException('Cache directory is not writable: ' . $this->directory);
        }
    }

    public function get(string $key): mixed
    {
        $path = $this->path($key);

        if (!is_file($path)) {
            return null;
        }

        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }

        try {
            $entry = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (!is_array($entry) || !isset($entry['expires']) || !is_int($entry['expires'])) {
            return null;
        }

        if ($entry['expires'] <= time()) {
            @unlink($path);

            return null;
        }

        return $entry['value'] ?? null;
    }

    public function set(string $key, mixed $value, int $ttl = 0): void
    {
        $payload = json_encode([
            'value' => $value,
            'expires' => time() + max(1, $ttl),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $path = $this->path($key);
        $temporary = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';

        if (file_put_contents($temporary, $payload) === false) {
            throw new StorageException('Cannot write cache file: ' . $temporary);
        }

        if (!@rename($temporary, $path)) {
            @unlink($temporary);
            throw new StorageException('Cannot replace cache file: ' . $path);
        }
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }

    private function path(string $key): string
    {
        return $this->directory . DIRECTORY_SEPARATOR . hash('sha256', $key) . '.json';
    }
}
