<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Security;

use FormSpamChecker\Check\BanCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Security\AutoBan;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class BanCheckTest extends TempDirTestCase
{
    private function request(string $ip): RequestData
    {
        return new RequestData(
            ['name' => 'Иван'],
            $ip,
            ['user-agent' => 'Mozilla/5.0 Chrome/140'],
            [],
            [],
            'POST',
            '/form',
            '',
            1_700_000_000,
            'contact',
        );
    }

    private function autoBan(bool $enabled = true): AutoBan
    {
        return new AutoBan(
            new Config(['autoban' => ['enabled' => $enabled, 'threshold' => 1, 'window' => 3600, 'ttl' => 86400]]),
            new MemoryStorage(),
        );
    }

    public function testDisabledCheck(): void
    {
        $outcome = (new BanCheck($this->autoBan(false)))->check($this->request('203.0.113.5'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertStringContainsString('disabled', $outcome->reason);
    }

    public function testNoIpIsUncertain(): void
    {
        $outcome = (new BanCheck($this->autoBan()))->check($this->request(''));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
    }

    public function testBannedIpIsHardSpam(): void
    {
        $autoBan = $this->autoBan();
        $autoBan->ban('203.0.113.5', 'spam', 100);

        $outcome = (new BanCheck($autoBan))->check($this->request('203.0.113.5'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(100, $outcome->score);
        self::assertStringContainsString('banned', $outcome->reason);
        self::assertSame('autoban', $outcome->check);
    }

    public function testCleanIpPasses(): void
    {
        $outcome = (new BanCheck($this->autoBan()))->check($this->request('203.0.113.6'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }
}
