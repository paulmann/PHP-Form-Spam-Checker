<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Security;

use FormSpamChecker\Security\Fail2Ban;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class Fail2BanTest extends TempDirTestCase
{
    public function testReportAppendsOneMachineReadableLine(): void
    {
        $path = $this->tempDir() . '/logs/f2b.log';
        $ban = new Fail2Ban($path, 'batterywizard.ru');

        self::assertTrue($ban->report('203.0.113.5', 'spam:keywords; links', 100, 'register'));
        self::assertFileExists($path);

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        self::assertCount(1, $lines);
        self::assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} PHPFSC BAN ip=203\.0\.113\.5 /',
            $lines[0],
        );
        self::assertStringContainsString('site=batterywizard.ru', $lines[0]);
        self::assertStringContainsString('form=register', $lines[0]);
        self::assertStringContainsString('score=100', $lines[0]);
        // Spaces and separators inside the reason become one token.
        self::assertStringContainsString('reason=spam:keywords;_links', $lines[0]);
        self::assertStringNotContainsString(' ', trim(explode('reason=', $lines[0])[1]));
    }

    public function testTwoReportsAppendTwoLines(): void
    {
        $path = $this->tempDir() . '/f2b.log';
        $ban = new Fail2Ban($path, 'conbat.ru');

        self::assertTrue($ban->report('203.0.113.6', 'waf', 90));
        self::assertTrue($ban->report('203.0.113.7', 'spam', 100));

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        self::assertCount(2, $lines);
    }

    public function testInvalidIpAndEmptyPathAreRejected(): void
    {
        $path = $this->tempDir() . '/f2b.log';

        self::assertFalse((new Fail2Ban($path, 'x'))->report('not-an-ip', 'spam', 100));
        self::assertFalse((new Fail2Ban($path, 'x'))->report('', 'spam', 100));
        self::assertFileDoesNotExist($path);

        self::assertFalse((new Fail2Ban('', 'x'))->report('203.0.113.8', 'spam', 100));
    }

    public function testNewlinesCannotBreakTheLogFormat(): void
    {
        $path = $this->tempDir() . '/f2b.log';
        (new Fail2Ban($path, 'site'))->report('203.0.113.9', "evil\ninjection", 100, "form\r\nname");

        $raw = (string) file_get_contents($path);
        self::assertCount(1, preg_split('/\R/', trim($raw)) ?: []);
        self::assertStringNotContainsString("\n", trim($raw));
    }
}
