<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\LinkCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class LinkCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testNoLinksIsClean(): void
    {
        $result = (new LinkCheck(new Config()))->check(
            $this->submission(['message' => 'Нужен отчёт за октябрь.']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testLinksWithinLimitAreClean(): void
    {
        $result = (new LinkCheck(new Config(['links' => ['max' => 2]])))->check(
            $this->submission(['message' => 'Смотрите https://example.ru/a и https://example.ru/b']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testTooManyLinksAreSuspicious(): void
    {
        $result = (new LinkCheck(new Config(['links' => ['max' => 1]])))->check(
            $this->submission(['message' => 'https://a.ru https://b.ru https://c.ru']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('links', $result->reason);
    }

    public function testShortenerIsSuspicious(): void
    {
        $result = (new LinkCheck(new Config()))->check(
            $this->submission(['message' => 'Переходите: https://bit.ly/abc123']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('shortener', $result->reason);
    }

    public function testObfuscatedLinkIsSuspicious(): void
    {
        $result = (new LinkCheck(new Config()))->check(
            $this->submission(['message' => 'Сайт hxxp://spam.example']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testExcludedFieldsAreNotScanned(): void
    {
        $result = (new LinkCheck(new Config()))->check(
            $this->submission(['website' => 'https://bit.ly/x', 'message' => 'обычный текст']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['links' => ['enabled' => false]]);
        $result = (new LinkCheck($config))->check(
            $this->submission(['message' => 'https://bit.ly/a https://bit.ly/b https://bit.ly/c']),
        );

        self::assertTrue($result->status->isClean());
    }
}
