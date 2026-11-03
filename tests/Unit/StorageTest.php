<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Storage\FileStorage;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class StorageTest extends TempDirTestCase
{
    public function testMemoryStorageCountsWithinTtl(): void
    {
        $storage = new MemoryStorage(1000);

        self::assertSame(1, $storage->increment('key', 60));
        self::assertSame(2, $storage->increment('key', 60));
        self::assertSame('2', $storage->get('key'));

        $storage->travel(61);

        self::assertNull($storage->get('key'));
        self::assertSame(1, $storage->increment('key', 60));
    }

    public function testMemoryStorageSetDeleteAndGc(): void
    {
        $storage = new MemoryStorage(1000);

        $storage->set('a', 'value', 10);
        self::assertSame('value', $storage->get('a'));
        $storage->delete('a');
        self::assertNull($storage->get('a'));

        $storage->set('b', 'value', 5);
        $storage->travel(6);
        $storage->gc();
        self::assertNull($storage->get('b'));
    }

    public function testFileStoragePersistsCountersAcrossInstances(): void
    {
        $dir = $this->tempDir();

        $first = new FileStorage($dir);
        self::assertSame(1, $first->increment('rate:203.0.113.1', 60));
        self::assertSame(2, $first->increment('rate:203.0.113.1', 60));

        $second = new FileStorage($dir);
        self::assertSame(3, $second->increment('rate:203.0.113.1', 60));
        self::assertSame('3', $second->get('rate:203.0.113.1'));
    }

    public function testFileStorageSetAndDelete(): void
    {
        $storage = new FileStorage($this->tempDir());

        $storage->set('token', 'abc', 60);
        self::assertSame('abc', $storage->get('token'));

        $storage->delete('token');
        self::assertNull($storage->get('token'));
    }

    public function testFileStorageHonoursTtl(): void
    {
        $dir = $this->tempDir();
        $storage = new FileStorage($dir);

        $storage->increment('short', 1);
        sleep(2);

        self::assertNull($storage->get('short'));
        self::assertSame(1, $storage->increment('short', 60));
    }

    public function testFileStorageGcRemovesExpiredEntries(): void
    {
        $dir = $this->tempDir();
        $storage = new FileStorage($dir);

        $storage->increment('expired', 1);
        $storage->increment('alive', 60);
        sleep(2);
        $storage->gc();

        $files = glob($dir . '/*.json');
        self::assertIsArray($files);
        self::assertCount(1, $files);
    }

    public function testFileStorageHandlesManyIncrements(): void
    {
        $storage = new FileStorage($this->tempDir());

        for ($i = 1; $i <= 50; $i++) {
            self::assertSame($i, $storage->increment('counter', 300));
        }
    }
}
