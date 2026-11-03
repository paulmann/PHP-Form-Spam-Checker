<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Security;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Integration\WafGuard;
use FormSpamChecker\Security\Fail2Ban;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;

/**
 * End-to-end wiring: a hard-spam verdict feeds Fail2Ban and the auto-ban, and
 * the next request from that IP is rejected by the BanCheck.
 */
final class SecurityIntegrationTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0';

    private function request(array $fields, string $ip = '203.0.113.50'): RequestData
    {
        return new RequestData(
            $fields,
            $ip,
            ['user-agent' => self::UA],
            [],
            [],
            'POST',
            '/register',
            '',
            1_700_000_000,
            'register',
        );
    }

    private function config(string $log): Config
    {
        return new Config([
            'storage' => ['driver' => 'memory'],
            'cache' => ['driver' => 'memory'],
            'log' => ['enabled' => false],
            'autoban' => ['enabled' => true, 'threshold' => 1, 'window' => 3600, 'ttl' => 86400],
            'fail2ban' => ['enabled' => true, 'log_path' => $log, 'site' => 'test.example', 'emit_on' => 'both', 'min_score' => 60],
        ]);
    }

    public function testSpamFeedsFail2BanAndAutobanBlocksNextRequest(): void
    {
        $log = $this->tempDir() . '/f2b.log';
        $checker = new SpamChecker($this->config($log), new MemoryStorage());

        $first = $checker->checkRequest($this->request(['name' => 'bot', 'website' => 'filled']));
        self::assertTrue($first->isSpam());
        self::assertFileExists($log);
        $line = (string) file_get_contents($log);
        self::assertStringContainsString('PHPFSC BAN ip=203.0.113.50', $line);
        self::assertStringContainsString('reason=spam:', $line);

        $second = $checker->checkRequest($this->request(['name' => 'Иван', 'email' => 'ivan@example.ru']));
        self::assertTrue($second->isSpam());
        self::assertStringContainsString('autoban', implode(' ', $second->reasons()));
    }

    public function testCleanTrafficNeverReports(): void
    {
        $log = $this->tempDir() . '/f2b.log';
        $checker = new SpamChecker($this->config($log), new MemoryStorage());

        $verdict = $checker->checkRequest($this->request(['name' => 'Иван', 'email' => 'ivan@example.ru', 'message' => 'Нужен отчёт.']));

        self::assertFalse($verdict->isSpam());
        self::assertFileDoesNotExist($log);
    }

    public function testCreateFail2BanHonoursConfig(): void
    {
        self::assertNull(SpamChecker::createFail2Ban(new Config()));

        $log = $this->tempDir() . '/f2b.log';
        $ban = SpamChecker::createFail2Ban($this->config($log));

        self::assertInstanceOf(Fail2Ban::class, $ban);
        self::assertSame($log, $ban->logPath());
    }

    public function testWafMonitorReportsToFail2Ban(): void
    {
        $dir = $this->tempDir();
        $log = $dir . '/f2b.log';
        $site = $dir . '/wafmon.php';

        file_put_contents($site, '<?php return ' . var_export([
            'site' => 'wafmon.example',
            'mode' => 'enforce',
            'form' => 'contact',
            'match' => [],
            'skip' => [],
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
                'waf' => ['enabled' => true, 'mode' => 'monitor'],
                'autoban' => ['enabled' => true, 'threshold' => 1],
                'fail2ban' => ['enabled' => true, 'log_path' => $log, 'site' => 'wafmon.example'],
            ],
        ], true) . ';');

        $guard = WafGuard::boot('wafmon', $dir);
        self::assertTrue($guard->enabled());

        $previousLog = ini_set('error_log', $dir . '/error.log');

        try {
            $result = $guard->run(
                ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/?q=1%20UNION%20SELECT%20x%20FROM%20y', 'REMOTE_ADDR' => '203.0.113.77', 'HTTP_HOST' => 'wafmon.example', 'HTTP_USER_AGENT' => self::UA],
            );
        } finally {
            ini_set('error_log', $previousLog === false ? '' : $previousLog);
        }

        self::assertFalse($result);
        self::assertFileExists($log);
        self::assertStringContainsString('PHPFSC BAN ip=203.0.113.77', (string) file_get_contents($log));
        self::assertStringContainsString('reason=waf:', (string) file_get_contents($log));
    }
}
