<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Bayes;

use FormSpamChecker\Bayes\CacheModelStorage;
use FormSpamChecker\Bayes\Classifier;
use FormSpamChecker\Cache\ArrayCache;
use FormSpamChecker\Check\BayesCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use PHPUnit\Framework\TestCase;

final class BayesCheckTest extends TestCase
{
    private const SPAM_TEXT = 'viagra casino bonus free money';
    private const HAM_TEXT = 'hello friend meeting tomorrow';

    public function testName(): void
    {
        self::assertSame('bayes', $this->check($this->trained())->name());
    }

    public function testDisabledReturnsHam(): void
    {
        $outcome = $this->check($this->trained(), ['enabled' => false])->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('disabled', $outcome->reason);
    }

    public function testUntrainedReturnsUncertain(): void
    {
        $classifier = new Classifier(new CacheModelStorage(new ArrayCache(1000)), 2);
        $outcome = $this->check($classifier, ['min_documents' => 20])->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame(0, $outcome->evidence['documents']);
        self::assertSame(20, $outcome->evidence['min_documents']);
        self::assertFalse($outcome->evidence['trained']);
    }

    public function testBelowMinDocumentsReturnsUncertain(): void
    {
        $outcome = $this->check($this->trained(), ['min_documents' => 100])
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame(4, $outcome->evidence['documents']);
        self::assertSame(100, $outcome->evidence['min_documents']);
        self::assertTrue($outcome->evidence['trained']);
    }

    public function testSpamTextIsSuspiciousNotHard(): void
    {
        $outcome = $this->check($this->trained(), ['threshold' => 0.5])
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertGreaterThan(0, $outcome->score);
        self::assertTrue($outcome->isFlagged());
        self::assertGreaterThan(0.5, $outcome->evidence['probability']);
        self::assertSame(0.5, $outcome->evidence['threshold']);
        self::assertSame(4, $outcome->evidence['documents']);
    }

    public function testHardModeReturnsSpam(): void
    {
        $outcome = $this->check($this->trained(), ['threshold' => 0.5, 'hard' => true])
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertGreaterThan(0, $outcome->score);
        self::assertLessThanOrEqual(100, $outcome->score);
    }

    public function testHamTextStaysHam(): void
    {
        $outcome = $this->check($this->trained())->check($this->request(self::HAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertArrayHasKey('probability', $outcome->evidence);
        self::assertLessThan(0.92, $outcome->evidence['probability']);
    }

    public function testEmptyTextScoresNeutral(): void
    {
        $outcome = $this->check($this->trained())->check(new RequestData(['message' => '   ']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame(0.5, $outcome->evidence['probability']);
    }

    public function testScoreScaleLimitsScore(): void
    {
        $outcome = $this->check($this->trained(), ['threshold' => 0.5, 'score_scale' => 50])
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertGreaterThan(0, $outcome->score);
        self::assertLessThanOrEqual(50, $outcome->score);
    }

    public function testThresholdBoundaryIsInclusive(): void
    {
        $classifier = $this->trained();
        $probability = $classifier->score(self::SPAM_TEXT);

        $outcome = $this->check($classifier, ['threshold' => $probability])
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertGreaterThan(0, $outcome->score);
    }

    public function testExcludedFieldsDoNotAffectProbability(): void
    {
        $classifier = $this->trained();
        $plain = $this->check($classifier, ['threshold' => 0.5])
            ->check($this->request(self::SPAM_TEXT));

        $withTechnicalFields = $this->check($classifier, ['threshold' => 0.5])->check(new RequestData([
            'message' => self::SPAM_TEXT,
            'website' => 'https://spam.example/viagra',
            '_fs_ts' => 'token',
            '_js' => '42',
            '_js_token' => 'signed',
            '_hp_0123456789ab' => 'filled',
        ]));

        self::assertSame($plain->evidence['probability'], $withTechnicalFields->evidence['probability']);
    }

    public function testRespectsFormScopedConfig(): void
    {
        $config = new Config([
            'bayes' => ['enabled' => true, 'min_documents' => 2, 'threshold' => 0.5],
            'forms' => [
                'contact' => ['bayes' => ['enabled' => false]],
            ],
        ]);

        $outcome = (new BayesCheck($this->trained(), $config->form('contact')))
            ->check($this->request(self::SPAM_TEXT));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame('disabled', $outcome->reason);
    }

    /**
     * @param array<string, mixed> $bayes
     */
    private function check(Classifier $classifier, array $bayes = []): BayesCheck
    {
        $config = new Config([
            'bayes' => array_merge(
                ['enabled' => true, 'min_documents' => 2, 'threshold' => 0.92, 'score_scale' => 100],
                $bayes,
            ),
        ]);

        return new BayesCheck($classifier, $config);
    }

    private function request(string $message): RequestData
    {
        return new RequestData(['message' => $message]);
    }

    private function trained(): Classifier
    {
        $classifier = new Classifier(new CacheModelStorage(new ArrayCache(1000)), 2);

        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train('casino poker viagra bonus', true);
        $classifier->train(self::HAM_TEXT, false);
        $classifier->train('hello friend dinner tonight', false);

        return $classifier;
    }
}
