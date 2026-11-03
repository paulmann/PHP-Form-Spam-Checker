<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\LanguageCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class LanguageCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testDisabledByDefault(): void
    {
        $result = (new LanguageCheck(new Config()))->check(
            $this->submission(['message' => 'Пpивет']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testMixedScriptWordIsSuspiciousWhenEnabled(): void
    {
        $config = new Config(['language' => ['enabled' => true]]);
        $result = (new LanguageCheck($config))->check(
            $this->submission(['message' => 'Пpивет, нужен отчёт']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testMonoscriptTextIsClean(): void
    {
        $config = new Config(['language' => ['enabled' => true]]);
        $result = (new LanguageCheck($config))->check(
            $this->submission(['message' => 'Привет, нужен отчёт']),
        );

        self::assertTrue($result->status->isClean());
    }
}
