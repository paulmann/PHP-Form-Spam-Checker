<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Security;

use FormSpamChecker\Config;
use FormSpamChecker\Security\AutoBan;
use FormSpamChecker\Security\Fail2Ban;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class AutoBanTest extends TempDirTestCase
{
    /**
     * @param array<string, mixed> $autoban
     */
    private function autoban(MemoryStorage $storage, array $autoban = [], ?Fail2Ban $fail2ban = null): AutoBan
    {
        $config = new Config(['autoban' => $autoban + [
            'enabled' => true,
            'threshold' => 3,
            'window' => 3600,
            'ttl' => 86400,
        ]]);

        return new AutoBan($config, $storage, $fail2ban);
    }

    public function testDisabledAutoBanNeverBans(): void
    {
        $autoBan = $this->autoban(new MemoryStorage(), ['enabled' => false]);

        self::assertFalse($autoBan->enabled());
        self::assertFalse($autoBan->recordAbuse('203.0.113.5', 'spam', 100));
        self::assertFalse($autoBan->isBanned('203.0.113.5'));
    }

    public function testThresholdBanAndUnban(): void
    {
        $storage = new MemoryStorage();
        $log = $this->tempDir() . '/f2b.log';
        $autoBan = $this->autoban($storage, [], new Fail2Ban($log, 'test'));

        self::assertFalse($autoBan->recordAbuse('203.0.113.10', 'spam', 90));
        self::assertFalse($autoBan->recordAbuse('203.0.113.10', 'spam', 90));
        self::assertFalse($autoBan->isBanned('203.0.113.10'));

        self::assertTrue($autoBan->recordAbuse('203.0.113.10', 'spam', 90));
        self::assertTrue($autoBan->isBanned('203.0.113.10'));
        self::assertStringContainsString('ip=203.0.113.10', (string) file_get_contents($log));

        // Already banned: further events do not re-ban or re-report.
        self::assertFalse($autoBan->recordAbuse('203.0.113.10', 'spam', 90));

        $autoBan->unban('203.0.113.10');
        self::assertFalse($autoBan->isBanned('203.0.113.10'));
    }

    public function testInvalidIpIsIgnored(): void
    {
        $storage = new MemoryStorage();
        $autoBan = $this->autoban($storage);

        self::assertFalse($autoBan->recordAbuse('nope', 'spam', 100));
        self::assertFalse($autoBan->isBanned(''));
        $autoBan->ban('nope');
        self::assertFalse($autoBan->isBanned('nope'));
    }

    public function testImmediateBanReportsToFail2Ban(): void
    {
        $storage = new MemoryStorage();
        $log = $this->tempDir() . '/f2b.log';
        $autoBan = $this->autoban($storage, [], new Fail2Ban($log, 'test'));

        $autoBan->ban('203.0.113.11', 'waf', 90, 'lead');

        self::assertTrue($autoBan->isBanned('203.0.113.11'));
        self::assertStringContainsString('reason=waf', (string) file_get_contents($log));
    }
}
