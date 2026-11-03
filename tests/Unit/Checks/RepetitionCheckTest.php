<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\LanguageCheck;
use FormSpamChecker\Checks\RepetitionCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class RepetitionCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testNormalTextIsClean(): void
    {
        $result = (new RepetitionCheck(new Config()))->check(
            $this->submission(['message' => 'Прошу подготовить отчёт за октябрь по прибору BCT-48.']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testLongCharacterRunIsSuspicious(): void
    {
        $result = (new RepetitionCheck(new Config()))->check(
            $this->submission(['message' => 'aaaaaaaaaaaaaaaaaaaaaaa']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testRepeatedWordIsSuspicious(): void
    {
        $result = (new RepetitionCheck(new Config()))->check(
            $this->submission(['message' => 'купить купить купить купить купить']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['repetition' => ['enabled' => false]]);
        $result = (new RepetitionCheck($config))->check(
            $this->submission(['message' => 'aaaaaaaaaaaaaaaaaaaa']),
        );

        self::assertTrue($result->status->isClean());
    }
}
