<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Behavioral;

use FormSpamChecker\Behavioral\Honeypot;
use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use PHPUnit\Framework\TestCase;

final class HoneypotTest extends TestCase
{
    private const SECRET = '0123456789abcdef0123456789abcdef';
    private const NOW = 1_800_000_000;

    public function testFieldNameIsDeterministicPerBucketAndForm(): void
    {
        $honeypot = new Honeypot($this->config());
        $name = $honeypot->fieldName('contact', self::NOW);

        self::assertSame($name, $honeypot->fieldName('contact', self::NOW));
        self::assertNotSame($name, $honeypot->fieldName('contact', self::NOW + 3600));
        self::assertNotSame($name, $honeypot->fieldName('register', self::NOW));
        self::assertStringStartsWith('_hp_', $name);
        self::assertMatchesRegularExpression('/^_hp_[0-9a-f]{12}$/', $name);
    }

    public function testCandidatesCoverCurrentAndPreviousBucket(): void
    {
        $honeypot = new Honeypot($this->config());

        self::assertSame(
            [
                $honeypot->fieldName('contact', self::NOW),
                $honeypot->fieldName('contact', self::NOW - 3600),
            ],
            $honeypot->candidates('contact', self::NOW),
        );
    }

    public function testVerifyFindsFilledCurrentBucket(): void
    {
        $honeypot = new Honeypot($this->config());
        $name = $honeypot->fieldName('contact', self::NOW);

        $data = new RequestData([$name => 'bot', 'message' => 'hello'], now: self::NOW);

        self::assertSame($name, $honeypot->verify($data, 'contact'));
    }

    public function testVerifyFindsFilledPreviousBucket(): void
    {
        $honeypot = new Honeypot($this->config());
        $name = $honeypot->fieldName('contact', self::NOW - 3600);

        $data = new RequestData([$name => 'bot'], now: self::NOW);

        self::assertSame($name, $honeypot->verify($data, 'contact'));
    }

    public function testVerifyReturnsNullForEmptyField(): void
    {
        $honeypot = new Honeypot($this->config());
        $name = $honeypot->fieldName('contact', self::NOW);

        $data = new RequestData([$name => '   '], now: self::NOW);

        self::assertNull($honeypot->verify($data, 'contact'));
    }

    public function testVerifyIgnoresExpiredBucket(): void
    {
        $honeypot = new Honeypot($this->config());
        $expired = $honeypot->fieldName('contact', self::NOW - 2 * 3600);

        $data = new RequestData([$expired => 'bot'], now: self::NOW);

        self::assertNull($honeypot->verify($data, 'contact'));
    }

    public function testVerifyUsesRequestClock(): void
    {
        $honeypot = new Honeypot($this->config());
        $past = self::NOW - 10 * 3600;
        $name = $honeypot->fieldName('contact', $past);

        $data = new RequestData([$name => 'bot'], now: $past);

        self::assertSame($name, $honeypot->verify($data, 'contact'));
    }

    public function testVerifyChecksConfiguredStaticFields(): void
    {
        $honeypot = new Honeypot($this->config(['static' => ['_trap']]));
        $data = new RequestData(['_trap' => 'filled'], now: self::NOW);

        self::assertSame('_trap', $honeypot->verify($data, 'contact'));
    }

    public function testStaticFieldsUseDedicatedKey(): void
    {
        $honeypot = new Honeypot($this->config(['static' => ['_a', '', '_a']]));

        self::assertSame(['_a'], $honeypot->staticFields());
    }

    public function testStaticFieldsFallBackToLegacyHoneypotFields(): void
    {
        $honeypot = new Honeypot($this->config(['static' => []]));

        self::assertSame(['website', '_fs_hp'], $honeypot->staticFields());
    }

    public function testPrefixFallsBackToDefault(): void
    {
        self::assertSame('_hp_', (new Honeypot($this->config(['field_prefix' => ''])))->prefix());
    }

    public function testSecretAndConfigurationState(): void
    {
        self::assertTrue((new Honeypot($this->config()))->isConfigured());
        self::assertSame(self::SECRET, (new Honeypot($this->config()))->secret());

        $short = new Honeypot($this->config(['secret' => 'short']));

        self::assertFalse($short->isConfigured());
    }

    public function testShortSecretFallsBackToNonSecretDerivation(): void
    {
        $honeypot = new Honeypot($this->config(['secret' => 'short']));
        $name = $honeypot->fieldName('contact', self::NOW);

        self::assertMatchesRegularExpression('/^_hp_[0-9a-f]{12}$/', $name);
        self::assertSame($name, $honeypot->fieldName('contact', self::NOW));
        self::assertStringNotContainsString('short', $name);
    }

    public function testBucket(): void
    {
        $honeypot = new Honeypot($this->config());

        self::assertSame(2, $honeypot->bucket(7200));
        self::assertSame(0, $honeypot->bucket(3599));
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
                ], $honeypot),
            ],
        ]);
    }
}
