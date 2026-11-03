<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Cache\Fake;

use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * In-memory PSR-6 pool good enough to drive the adapter: items keep their value,
 * hit flag and the exact expiry call the adapter made.
 */
final class FakePsr6Pool implements CacheItemPoolInterface
{
    /**
     * @var array<string, FakePsr6Item>
     */
    public array $items = [];

    public function getItem(string $key): CacheItemInterface
    {
        return $this->items[$key] ??= new FakePsr6Item($key);
    }

    /**
     * @param  array<string>                        $keys
     * @return iterable<string, CacheItemInterface>
     */
    public function getItems(array $keys = []): iterable
    {
        $items = [];

        foreach ($keys as $key) {
            $items[$key] = $this->getItem($key);
        }

        return $items;
    }

    public function hasItem(string $key): bool
    {
        return isset($this->items[$key]) && $this->items[$key]->isHit();
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function deleteItem(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    /**
     * @param array<string> $keys
     */
    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            unset($this->items[$key]);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        if (!$item instanceof FakePsr6Item) {
            return false;
        }

        $item->markHit();
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        return $this->save($item);
    }

    public function commit(): bool
    {
        return true;
    }
}
