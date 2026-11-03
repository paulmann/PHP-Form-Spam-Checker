<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Cache;

use FormSpamChecker\Cache\Psr16CacheAdapter;
use FormSpamChecker\Tests\Unit\Cache\Fake\FakePsr16Cache;
use PHPUnit\Framework\TestCase;

final class Psr16CacheAdapterTest extends TestCase
{
    private FakePsr16Cache $cache;

    private Psr16CacheAdapter $adapter;

    protected function setUp(): void
    {
        $this->cache = new FakePsr16Cache();
        $this->adapter = new Psr16CacheAdapter($this->cache);
    }

    public function testGetReturnsTheStoredValue(): void
    {
        $this->cache->values['k'] = ['score' => 42];

        self::assertSame(['score' => 42], $this->adapter->get('k'));
    }

    public function testGetReturnsNullOnAMiss(): void
    {
        self::assertNull($this->adapter->get('missing'));
    }

    public function testPositiveTtlIsForwardedAsAnInteger(): void
    {
        $this->adapter->set('k', 'v', 3600);

        self::assertSame(3600, $this->cache->ttls['k']);
        self::assertSame('v', $this->cache->values['k']);
    }

    public function testZeroTtlMeansThePsr16DefaultLifetime(): void
    {
        $this->adapter->set('k', 'v', 0);

        self::assertNull($this->cache->ttls['k']);
    }

    public function testHasAndDeleteDelegateToThePsr16Cache(): void
    {
        $this->adapter->set('k', 'v');
        self::assertTrue($this->adapter->has('k'));

        $this->adapter->delete('k');
        self::assertFalse($this->adapter->has('k'));
        self::assertArrayNotHasKey('k', $this->cache->values);
    }
}
