<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\KeywordCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class KeywordCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testCleanTextIsClean(): void
    {
        $result = (new KeywordCheck(new Config()))->check(
            $this->submission(['message' => 'Прошу подготовить отчёт по протоколу испытаний.']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testSpamWordsAddScore(): void
    {
        $result = (new KeywordCheck(new Config()))->check(
            $this->submission(['message' => 'Казино онлайн, ставки на спорт и быстрый займ!']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertGreaterThan(0, $result->score);
        self::assertStringContainsString('казино', $result->reason);
    }

    public function testExcludedFieldsAreNotScanned(): void
    {
        $config = new Config();
        $result = (new KeywordCheck($config))->check(
            $this->submission(['website' => 'casino', 'message' => 'нормальный текст']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testCustomWordsAreSupported(): void
    {
        $config = new Config(['keywords' => ['words' => ['продвижение в топ']]]);
        $result = (new KeywordCheck($config))->check(
            $this->submission(['message' => 'Продвижение в топ за неделю']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testRegexPatternsAreSupported(): void
    {
        $config = new Config(['keywords' => ['patterns' => ['/\b\+?\d{10,}\b/']]]);
        $result = (new KeywordCheck($config))->check(
            $this->submission(['message' => 'звоните 89001234567']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testInvalidPatternIsIgnored(): void
    {
        $config = new Config(['keywords' => ['patterns' => ['/broken(']]]);
        $result = (new KeywordCheck($config))->check($this->submission(['message' => 'обычный текст']));

        self::assertTrue($result->status->isClean());
    }

    public function testScanFieldsRestrictsInspection(): void
    {
        $config = new Config(['keywords' => ['scan_fields' => ['message']]]);
        $result = (new KeywordCheck($config))->check(
            $this->submission(['name' => 'casino', 'message' => 'обычный текст']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testMultibyteCaseInsensitive(): void
    {
        $result = (new KeywordCheck(new Config()))->check(
            $this->submission(['message' => 'КАЗИНО']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['keywords' => ['enabled' => false]]);
        $result = (new KeywordCheck($config))->check($this->submission(['message' => 'казино']));

        self::assertTrue($result->status->isClean());
    }
}
