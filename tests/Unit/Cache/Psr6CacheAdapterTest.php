<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Cache;

use FormSpamChecker\Cache\Psr6CacheAdapter;
use FormSpamChecker\Tests\Unit\Cache\Fake\FakePsr6Item;
use FormSpamChecker\Tests\Unit\Cache\Fake\FakePsr6Pool;
use PHPUnit\Framework\TestCase;

final class Psr6CacheAdapterTest extends TestCase
{
    private FakePsr6Pool $pool;

    private Psr6CacheAdapter $adapter;

    protected function setUp(): void
    {
        $this->pool = new FakePsr6Pool();
        $this->adapter = new Psr6CacheAdapter($this->pool);
    }

    public function testSetAndGetRoundTrip(): void
    {
        $this->adapter->set('abuseipdb:203.0.113.5', ['status' => 'ham'], 600);

        self::assertSame(['status' => 'ham'], $this->adapter->get('abuseipdb:203.0.113.5'));
        self::assertTrue($this->adapter->has('abuseipdb:203.0.113.5'));
    }

    public function testGetReturnsNullOnAMiss(): void
    {
        self::assertNull($this->adapter->get('missing'));
    }

    public function testPositiveTtlIsPassedToExpiresAfter(): void
    {
        $this->adapter->set('k', 'v', 600);

        $item = $this->pool->items[$this->singleKey()];
        self::assertTrue($item->expiresAfterCalled);
        self::assertSame(600, $item->lastExpiresAfter);
    }

    public function testZeroTtlMeansNoExpiration(): void
    {
        $this->adapter->set('k', 'v');

        $item = $this->pool->items[$this->singleKey()];
        self::assertTrue($item->expiresAfterCalled);
        self::assertNull($item->lastExpiresAfter);
    }

    public function testDeleteRemovesTheItem(): void
    {
        $this->adapter->set('k', 'v');
        $this->adapter->delete('k');

        self::assertFalse($this->adapter->has('k'));
        self::assertSame([], $this->pool->items);
    }

    public function testColonsInLogicalKeysAreReplacedByASafeDeterministicKey(): void
    {
        $this->adapter->set('abuseipdb:203.0.113.5', 'v');

        $key = $this->singleKey();

        self::assertMatchesRegularExpression('/^fsc_[a-f0-9]{48}$/', $key);
        self::assertStringNotContainsString(':', $key);

        // The same logical key maps to the same pool item on every call.
        self::assertSame('v', $this->adapter->get('abuseipdb:203.0.113.5'));
        self::assertSame([$key], array_keys($this->pool->items));
    }

    public function testDifferentLogicalKeysMapToDifferentItems(): void
    {
        $this->adapter->set('a', '1');
        $this->adapter->set('b', '2');

        self::assertCount(2, $this->pool->items);
    }

    public function testSavedItemIsMarkedAsHit(): void
    {
        $this->adapter->set('k', 'v');

        $item = $this->pool->items[$this->singleKey()];
        self::assertInstanceOf(FakePsr6Item::class, $item);
        self::assertTrue($item->isHit());
    }

    private function singleKey(): string
    {
        $keys = array_keys($this->pool->items);
        self::assertCount(1, $keys);

        return (string) $keys[0];
    }
}
