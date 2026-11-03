<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\HoneypotCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class HoneypotCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testFilledHoneypotIsSpam(): void
    {
        $result = (new HoneypotCheck(new Config()))->check($this->submission(['website' => 'http://spam.example']));

        self::assertSame(Status::Spam, $result->status);
        self::assertSame('honeypot', $result->check);
        self::assertStringContainsString('website', $result->reason);
    }

    public function testCustomHoneypotFieldIsDetected(): void
    {
        $config = new Config(['honeypot' => ['fields' => ['my_trap']]]);
        $result = (new HoneypotCheck($config))->check($this->submission(['my_trap' => 'x']));

        self::assertSame(Status::Spam, $result->status);
    }

    public function testEmptyOrMissingHoneypotIsClean(): void
    {
        $check = new HoneypotCheck(new Config());

        self::assertTrue($check->check($this->submission(['website' => '']))->status->isClean());
        self::assertTrue($check->check($this->submission([]))->status->isClean());
        self::assertTrue($check->check($this->submission(['website' => '   ']))->status->isClean());
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['honeypot' => ['enabled' => false]]);
        $result = (new HoneypotCheck($config))->check($this->submission(['website' => 'spam']));

        self::assertTrue($result->status->isClean());
    }

    public function testTrimmedValueIsUsed(): void
    {
        $result = (new HoneypotCheck(new Config()))->check($this->submission(['website' => '   ']));

        self::assertTrue($result->status->isClean());
    }
}
