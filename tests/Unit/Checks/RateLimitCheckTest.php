<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\RateLimitCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class RateLimitCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testRequestsWithinLimitAreClean(): void
    {
        $storage = new MemoryStorage();
        $check = new RateLimitCheck(new Config(['rate_limit' => ['max' => 3]]), $storage);

        self::assertTrue($check->check($this->submission([]))->status->isClean());
        self::assertTrue($check->check($this->submission([]))->status->isClean());
        self::assertTrue($check->check($this->submission([]))->status->isClean());
    }

    public function testExceedingLimitIsSpam(): void
    {
        $storage = new MemoryStorage();
        $check = new RateLimitCheck(new Config(['rate_limit' => ['max' => 2]]), $storage);

        $check->check($this->submission([]));
        $check->check($this->submission([]));
        $result = $check->check($this->submission([]));

        self::assertSame(Status::Spam, $result->status);
        self::assertStringContainsString('rate limit exceeded', $result->reason);
    }

    public function testLimitIsPerIp(): void
    {
        $storage = new MemoryStorage();
        $check = new RateLimitCheck(new Config(['rate_limit' => ['max' => 1]]), $storage);

        self::assertTrue($check->check($this->submission([], ['ip' => '203.0.113.1']))->status->isClean());
        self::assertTrue($check->check($this->submission([], ['ip' => '203.0.113.2']))->status->isClean());
        self::assertSame(Status::Spam, $check->check($this->submission([], ['ip' => '203.0.113.1']))->status);
    }

    public function testCounterExpiresAfterWindow(): void
    {
        $storage = new MemoryStorage(1_000);
        $check = new RateLimitCheck(new Config(['rate_limit' => ['max' => 1, 'window' => 60]]), $storage);

        self::assertTrue($check->check($this->submission([]))->status->isClean());
        self::assertSame(Status::Spam, $check->check($this->submission([]))->status);

        $storage->travel(61);

        self::assertTrue($check->check($this->submission([]))->status->isClean());
    }

    public function testMissingIpIsClean(): void
    {
        $check = new RateLimitCheck(new Config(), new MemoryStorage());
        $result = $check->check($this->submission([], ['ip' => '']));

        self::assertTrue($result->status->isClean());
    }

    public function testDisabledCheckIsClean(): void
    {
        $check = new RateLimitCheck(
            new Config(['rate_limit' => ['enabled' => false]]),
            new MemoryStorage(),
        );

        self::assertTrue($check->check($this->submission([]))->status->isClean());
    }

    public function testPerFormCounterCanBeShared(): void
    {
        $storage = new MemoryStorage();
        $check = new RateLimitCheck(
            new Config(['rate_limit' => ['max' => 1, 'per_form' => false]]),
            $storage,
        );

        self::assertTrue($check->check($this->submission([], [], 'contact'))->status->isClean());
        self::assertSame(Status::Spam, $check->check($this->submission([], [], 'register'))->status);
    }
}
