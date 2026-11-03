<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network\Log;

use FormSpamChecker\Log\Psr3LoggerAdapter;
use FormSpamChecker\Tests\Unit\Network\Log\Fake\FakePsrLogger;
use PHPUnit\Framework\TestCase;

final class Psr3LoggerAdapterTest extends TestCase
{
    private FakePsrLogger $logger;

    private Psr3LoggerAdapter $adapter;

    protected function setUp(): void
    {
        $this->logger = new FakePsrLogger();
        $this->adapter = new Psr3LoggerAdapter($this->logger);
    }

    public function testErrorIsForwardedWithContext(): void
    {
        $this->adapter->error('lookup failed', ['ip' => '203.0.113.9']);

        self::assertSame(
            [['level' => 'error', 'message' => 'lookup failed', 'context' => ['ip' => '203.0.113.9']]],
            $this->logger->entries,
        );
    }

    public function testEveryConvenienceLevelIsForwarded(): void
    {
        $this->adapter->warning('w');
        $this->adapter->info('i');
        $this->adapter->debug('d');

        self::assertSame(['warning', 'info', 'debug'], array_column($this->logger->entries, 'level'));
    }

    public function testGenericLogForwardsTheLevelVerbatim(): void
    {
        $this->adapter->log('notice', 'custom', ['k' => 'v']);

        self::assertSame('notice', $this->logger->entries[0]['level']);
        self::assertSame('custom', $this->logger->entries[0]['message']);
        self::assertSame(['k' => 'v'], $this->logger->entries[0]['context']);
    }
}
