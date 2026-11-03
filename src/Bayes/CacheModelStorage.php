<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

use FormSpamChecker\Cache\CacheInterface;
use JsonException;

/**
 * Stores the Bayesian model as one JSON document in a `CacheInterface`.
 *
 * The whole model is written with a single `set()` call, so the cache adapter
 * is the only component that has to guarantee atomicity (the bundled `FileCache`
 * and `ArrayCache` replace the value as a whole). An unreadable or future-format
 * payload is treated as "no model yet" instead of throwing, which keeps the
 * spam path fail-open.
 */
final readonly class CacheModelStorage implements ModelStorageInterface
{
    public const DEFAULT_KEY = 'bayes.model';

    public function __construct(
        private CacheInterface $cache,
        private string $key = self::DEFAULT_KEY,
    ) {}

    public function key(): string
    {
        return $this->key;
    }

    public function load(): ?Model
    {
        $raw = $this->cache->get($this->key);

        // Some adapters (and tests) hand back the decoded value directly.
        if (\is_array($raw)) {
            return Model::fromArray($raw);
        }

        if (!\is_string($raw)) {
            return null;
        }

        try {
            $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return \is_array($data) ? Model::fromArray($data) : null;
    }

    public function save(Model $model): void
    {
        $json = json_encode(
            $model->toArray(),
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
        );

        $this->cache->set($this->key, $json);
    }

    public function delete(): void
    {
        $this->cache->delete($this->key);
    }
}
