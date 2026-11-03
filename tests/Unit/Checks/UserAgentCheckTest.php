<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\UserAgentCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class UserAgentCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testRealBrowserIsClean(): void
    {
        $result = (new UserAgentCheck(new Config()))->check($this->submission(['name' => 'Иван']));

        self::assertTrue($result->status->isClean());
    }

    public function testCurlUserAgentIsSpam(): void
    {
        $result = (new UserAgentCheck(new Config()))->check(
            $this->submission([], ['userAgent' => 'curl/8.5.0']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testHeadlessBrowserIsSpam(): void
    {
        $result = (new UserAgentCheck(new Config()))->check(
            $this->submission([], ['userAgent' => 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/140.0']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testScannerIsSpam(): void
    {
        $result = (new UserAgentCheck(new Config()))->check(
            $this->submission([], ['userAgent' => 'Mozilla/5.0 (compatible; SQLSpider/1.7.0)']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testEmptyUserAgentIsSuspiciousByDefault(): void
    {
        $result = (new UserAgentCheck(new Config()))->check($this->submission([], ['userAgent' => '']));

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testEmptyUserAgentCanBeAllowed(): void
    {
        $config = new Config(['user_agent' => ['allow_empty' => true]]);
        $result = (new UserAgentCheck($config))->check($this->submission([], ['userAgent' => '']));

        self::assertTrue($result->status->isClean());
    }

    public function testExtraBlocklistIsApplied(): void
    {
        $config = new Config(['user_agent' => ['extra_blocklist' => ['MyIntegrationBot']]]);
        $result = (new UserAgentCheck($config))->check(
            $this->submission([], ['userAgent' => 'MyIntegrationBot/1.0']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['user_agent' => ['enabled' => false]]);
        $result = (new UserAgentCheck($config))->check($this->submission([], ['userAgent' => 'curl/8']));

        self::assertTrue($result->status->isClean());
    }

    public function testMobileBrowserIsClean(): void
    {
        $ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 '
            . '(KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1';

        $result = (new UserAgentCheck(new Config()))->check($this->submission([], ['userAgent' => $ua]));

        self::assertTrue($result->status->isClean());
    }
}
