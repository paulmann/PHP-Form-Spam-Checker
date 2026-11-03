<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Behavioral;

use FormSpamChecker\Behavioral\Honeypot;
use FormSpamChecker\Check\DynamicHoneypotCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use PHPUnit\Framework\TestCase;

final class DynamicHoneypotCheckTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const NOW = 1_800_000_000;

    public function testName(): void
    {
        self::assertSame('dynamic_honeypot', (new DynamicHoneypotCheck($this->config()))->name());
    }

    public function testFilledCurrentBucketIsSpam(): void
    {
        $config = $this->config();
        $name = (new Honeypot($config))->fieldName('contact', self::NOW);

        $outcome = (new DynamicHoneypotCheck($config))->check(new RequestData([
            'message' => 'hello',
            $name => 'bot value',
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(100, $outcome->score);
        self::assertSame($name, $outcome->evidence['field']);
        self::assertSame('bot value', $outcome->evidence['value']);
    }

    public function testFilledPreviousBucketIsSpam(): void
    {
        $config = $this->config();
        $name = (new Honeypot($config))->fieldName('contact', self::NOW - 3600);

        $outcome = (new DynamicHoneypotCheck($config))->check(new RequestData([
            $name => 'bot',
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame($name, $outcome->evidence['field']);
    }

    public function testMissingExpectedFieldIsSuspicious(): void
    {
        $outcome = (new DynamicHoneypotCheck($this->config()))->check(new RequestData([
            'message' => 'hello',
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(10, $outcome->score);
        self::assertTrue($outcome->isFlagged());
        self::assertCount(2, $outcome->evidence['expected']);
    }

    public function testEmptyHoneypotIsHam(): void
    {
        $config = $this->config();
        $name = (new Honeypot($config))->fieldName('contact', self::NOW);

        $outcome = (new DynamicHoneypotCheck($config))->check(new RequestData([
            $name => '   ',
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    public function testShortSecretFailsOpen(): void
    {
        $outcome = (new DynamicHoneypotCheck($this->config(['secret' => 'short'])))
            ->check(new RequestData(['message' => 'hello'], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::ERROR, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertFalse($outcome->isFlagged());
        self::assertStringContainsString('secret', $outcome->reason);
    }

    public function testMissingScoreIsConfigurable(): void
    {
        $outcome = (new DynamicHoneypotCheck($this->config(['missing_score' => 25])))
            ->check(new RequestData([], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(25, $outcome->score);
    }

    public function testExpiredBucketAloneCountsAsMissing(): void
    {
        $config = $this->config();
        $expired = (new Honeypot($config))->fieldName('contact', self::NOW - 2 * 3600);

        $outcome = (new DynamicHoneypotCheck($config))->check(new RequestData([
            $expired => 'bot',
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(10, $outcome->score);
    }

    public function testStaticModeFilledFieldIsSpam(): void
    {
        $outcome = (new DynamicHoneypotCheck($this->config([
            'dynamic' => false,
            'static' => ['_trap'],
        ])))->check(new RequestData(['_trap' => 'bot'], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(100, $outcome->score);
        self::assertArrayHasKey('_trap', $outcome->evidence['fields']);
    }

    public function testStaticModeMissingFieldIsHam(): void
    {
        $outcome = (new DynamicHoneypotCheck($this->config([
            'dynamic' => false,
            'static' => ['_trap'],
        ])))->check(new RequestData(['message' => 'hello'], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    public function testStaticModeUsesLegacyHoneypotFields(): void
    {
        $config = new Config([
            'behavioral' => ['honeypot' => ['dynamic' => false]],
            'honeypot' => ['fields' => ['website']],
        ]);

        $outcome = (new DynamicHoneypotCheck($config))
            ->check(new RequestData(['website' => 'https://spam.example'], formId: 'contact'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
    }

    public function testStaticModeWithoutFieldsIsHam(): void
    {
        $config = new Config([
            'behavioral' => ['honeypot' => ['dynamic' => false, 'static' => []]],
            'honeypot' => ['fields' => []],
        ]);

        $outcome = (new DynamicHoneypotCheck($config))->check(new RequestData([], formId: 'contact'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame('static honeypot not configured', $outcome->reason);
    }

    /**
     * @param array<string, mixed> $honeypot
     */
    private function config(array $honeypot = []): Config
    {
        return new Config([
            'behavioral' => [
                'honeypot' => array_merge([
                    'dynamic' => true,
                    'field_prefix' => '_hp_',
                    'secret' => self::SECRET,
                    'missing_score' => 10,
                    'static' => [],
                ], $honeypot),
            ],
        ]);
    }
}
