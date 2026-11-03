<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Check\LanguageCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Pipeline\SpamPipeline;
use PHPUnit\Framework\TestCase;

/**
 * Cyrillic requirement for name-like fields (`language.require_cyrillic`).
 */
final class LanguageCyrillicTest extends TestCase
{
    private function request(array $fields): RequestData
    {
        return new RequestData(
            $fields,
            '203.0.113.10',
            ['user-agent' => 'Mozilla/5.0 Chrome/140'],
            [],
            [],
            'POST',
            '/register',
            '',
            1_700_000_000,
            'register',
        );
    }

    private function config(array $language = []): Config
    {
        return new Config(['language' => $language + [
            'enabled' => true,
            'require_cyrillic' => true,
            'missing_score' => 60,
            'max_score' => 100,
            'min_letters' => 2,
        ]]);
    }

    public function testLatinOnlyNameIsSuspicious(): void
    {
        $outcome = (new LanguageCheck($this->config()))->check($this->request(['name' => 'John Smith']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(60, $outcome->score);
        self::assertStringContainsString('no Cyrillic', $outcome->reason);
        self::assertSame(['name'], $outcome->evidence['fields_without_cyrillic']);
    }

    public function testCyrillicNamePasses(): void
    {
        $outcome = (new LanguageCheck($this->config()))->check($this->request(['name' => 'Иван']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    public function testOnlyConfiguredNameFieldsAreChecked(): void
    {
        $outcome = (new LanguageCheck($this->config()))->check($this->request([
            'name' => 'Иван',
            'company' => 'ACME Corp',
            'email' => 'ivan@example.com',
            'message' => 'Please call me back',
        ]));

        self::assertSame(0, $outcome->score, 'company/email/message must not be punished for Latin');
    }

    public function testFieldNameVariantsAndShortValues(): void
    {
        $check = new LanguageCheck($this->config());

        $variant = $check->check($this->request(['FirstName' => 'John']));
        self::assertSame(60, $variant->score);
        self::assertSame(['FirstName'], $variant->evidence['fields_without_cyrillic']);

        $short = $check->check($this->request(['name' => 'A']));
        self::assertSame(0, $short->score, 'single-letter values are ignored (min_letters=2)');
    }

    public function testTwoLatinFieldsDoubleTheScore(): void
    {
        $outcome = (new LanguageCheck($this->config()))->check($this->request([
            'name' => 'John',
            'surname' => 'Smith',
        ]));

        self::assertSame(120 - 20, $outcome->score === 100 ? 100 : $outcome->score);
        self::assertSame(100, $outcome->score, 'score is capped by max_score');
    }

    public function testLatinNameReachesSpamThroughThePipeline(): void
    {
        $config = $this->config();
        $verdict = (new SpamPipeline([new LanguageCheck($config)]))->process(
            $this->request(['name' => 'John Smith']),
            $config,
        );

        self::assertTrue($verdict->isSpam(), '60 points at the spam threshold blocks a Latin-only name');
    }

    public function testDisabledByDefaultAndFeatureOffKeepsLatinNames(): void
    {
        self::assertSame(
            CheckStatus::HAM,
            (new LanguageCheck(new Config()))->check($this->request(['name' => 'John']))->status,
        );

        $off = new LanguageCheck(new Config(['language' => ['enabled' => true]]));
        self::assertSame(0, $off->check($this->request(['name' => 'John']))->score);
    }
}
