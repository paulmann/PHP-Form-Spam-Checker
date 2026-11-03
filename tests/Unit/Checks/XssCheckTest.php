<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\XssCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class XssCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testNormalTextIsClean(): void
    {
        $result = (new XssCheck(new Config()))->check(
            $this->submission(['message' => 'Отчёт во вложении, спасибо.']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testScriptTagIsSpam(): void
    {
        $result = (new XssCheck(new Config()))->check(
            $this->submission(['message' => '<script>alert(document.cookie)</script>']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testJavascriptUriIsSpam(): void
    {
        $result = (new XssCheck(new Config()))->check(
            $this->submission(['message' => 'click javascript:alert(1)']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testEventHandlerIsSpam(): void
    {
        $result = (new XssCheck(new Config()))->check(
            $this->submission(['message' => '<img src=x onerror=alert(1)>']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testEncodedPayloadIsSuspicious(): void
    {
        $result = (new XssCheck(new Config()))->check(
            $this->submission(['message' => '&#60;script&#62;alert(1)&#60;/script&#62;']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['xss' => ['enabled' => false]]);
        $result = (new XssCheck($config))->check(
            $this->submission(['message' => '<script>alert(1)</script>']),
        );

        self::assertTrue($result->status->isClean());
    }
}
