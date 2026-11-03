<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\LengthCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class LengthCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testNormalLengthIsClean(): void
    {
        $result = (new LengthCheck(new Config()))->check(
            $this->submission(['message' => str_repeat('а', 100)]),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testLongFieldIsSuspicious(): void
    {
        $config = new Config(['length' => ['max' => 20, 'hard_max' => 100]]);
        $result = (new LengthCheck($config))->check(
            $this->submission(['message' => str_repeat('а', 30)]),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testVeryLongFieldIsSpam(): void
    {
        $config = new Config(['length' => ['max' => 20, 'hard_max' => 50]]);
        $result = (new LengthCheck($config))->check(
            $this->submission(['message' => str_repeat('а', 60)]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testControlCharactersAreSpam(): void
    {
        $result = (new LengthCheck(new Config()))->check(
            $this->submission(['message' => "текст\x00с нулём"]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testExcludedFieldsAreNotChecked(): void
    {
        $config = new Config(['length' => ['max' => 5, 'hard_max' => 10]]);
        $result = (new LengthCheck($config))->check(
            $this->submission(['website' => str_repeat('x', 100), 'message' => 'ok']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['length' => ['enabled' => false]]);
        $result = (new LengthCheck($config))->check(
            $this->submission(['message' => str_repeat('x', 30_000)]),
        );

        self::assertTrue($result->status->isClean());
    }
}
