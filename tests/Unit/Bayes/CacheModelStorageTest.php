<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Bayes;

use FormSpamChecker\Bayes\CacheModelStorage;
use FormSpamChecker\Bayes\Model;
use FormSpamChecker\Cache\ArrayCache;
use PHPUnit\Framework\TestCase;

final class CacheModelStorageTest extends TestCase
{
    private ArrayCache $cache;

    protected function setUp(): void
    {
        $this->cache = new ArrayCache(1000);
    }

    public function testSaveLoadRoundTrip(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $model = new Model(['viagra' => 2, 'казино' => 1], ['hello' => 3], 4, 5);

        $storage->save($model);
        $loaded = $storage->load();

        self::assertInstanceOf(Model::class, $loaded);
        self::assertSame($model->toArray(), $loaded->toArray());
    }

    public function testLoadWithoutModelReturnsNull(): void
    {
        self::assertNull((new CacheModelStorage($this->cache))->load());
    }

    public function testCorruptJsonReturnsNull(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $this->cache->set(CacheModelStorage::DEFAULT_KEY, '{not json');

        self::assertNull($storage->load());
    }

    public function testArrayPayloadIsAccepted(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $model = new Model(['a' => 1], ['b' => 1], 1, 1);
        $this->cache->set(CacheModelStorage::DEFAULT_KEY, $model->toArray());

        self::assertSame($model->toArray(), $storage->load()?->toArray());
    }

    public function testUnknownPayloadShapeReturnsNull(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $this->cache->set(CacheModelStorage::DEFAULT_KEY, '42');

        self::assertNull($storage->load());
    }

    public function testDeleteRemovesModel(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $storage->save(new Model(['a' => 1], [], 1, 0));

        $storage->delete();

        self::assertNull($storage->load());
    }

    public function testCustomKeyIsUsed(): void
    {
        $storage = new CacheModelStorage($this->cache, 'custom.model');

        self::assertSame('custom.model', $storage->key());
        $storage->save(new Model(['a' => 1], [], 1, 0));
        self::assertNull((new CacheModelStorage($this->cache))->load());
        self::assertNotNull($storage->load());
    }

    public function testJsonKeepsUnicodeTokens(): void
    {
        $storage = new CacheModelStorage($this->cache);
        $storage->save(new Model(['казино' => 4], [], 1, 0));

        $raw = $this->cache->get(CacheModelStorage::DEFAULT_KEY);

        self::assertIsString($raw);
        self::assertStringContainsString('казино', $raw);
        self::assertSame(4, $storage->load()?->spamTokens['казино']);
    }
}
