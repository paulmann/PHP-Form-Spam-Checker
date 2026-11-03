<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Behavioral;

use FormSpamChecker\Behavioral\JsChallenge;
use FormSpamChecker\Check\JsChallengeCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use PHPUnit\Framework\TestCase;

final class JsChallengeCheckTest extends TestCase
{
    private const SECRET = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';
    private const NOW = 1_800_000_000;

    public function testName(): void
    {
        self::assertSame('js_challenge', (new JsChallengeCheck($this->config()))->name());
    }

    public function testDisabledReturnsHam(): void
    {
        $outcome = (new JsChallengeCheck($this->config(['enabled' => false])))
            ->check(new RequestData([], now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('disabled', $outcome->reason);
    }

    public function testValidAnswerPasses(): void
    {
        $config = $this->config();
        $challenge = new JsChallenge($config);
        $issued = $challenge->issue('contact', self::NOW);

        $outcome = (new JsChallengeCheck($config))->check(new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $issued['token'],
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('js challenge passed', $outcome->reason);
    }

    public function testMissingChallengeIsSuspiciousNotSpam(): void
    {
        $outcome = (new JsChallengeCheck($this->config()))
            ->check(new RequestData(['message' => 'hello'], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(15, $outcome->score);
        self::assertTrue($outcome->isFlagged());
        self::assertFalse($outcome->evidence['answer_present']);
        self::assertFalse($outcome->evidence['token_present']);
    }

    public function testInvalidAnswerIsSuspicious(): void
    {
        $config = $this->config();
        $issued = (new JsChallenge($config))->issue('contact', self::NOW);

        $outcome = (new JsChallengeCheck($config))->check(new RequestData([
            '_js' => '999',
            '_js_token' => $issued['token'],
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(15, $outcome->score);
        self::assertStringContainsString('invalid', $outcome->reason);
    }

    public function testShortSecretFailsOpen(): void
    {
        $outcome = (new JsChallengeCheck($this->config(['secret' => 'short'])))
            ->check(new RequestData([], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::ERROR, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertStringContainsString('secret', $outcome->reason);
    }

    public function testMissingScoreIsConfigurable(): void
    {
        $outcome = (new JsChallengeCheck($this->config(['missing_score' => 25])))
            ->check(new RequestData([], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(25, $outcome->score);
    }

    public function testCustomFieldName(): void
    {
        $config = $this->config(['field' => '_human']);
        $challenge = new JsChallenge($config);
        $issued = $challenge->issue('contact', self::NOW);

        $outcome = (new JsChallengeCheck($config))->check(new RequestData([
            '_human' => $challenge->expectedAnswer($issued['challenge']),
            '_human_token' => $issued['token'],
        ], formId: 'contact', now: self::NOW));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    /**
     * @param array<string, mixed> $js
     */
    private function config(array $js = []): Config
    {
        return new Config([
            'behavioral' => [
                'js_challenge' => array_merge([
                    'enabled' => true,
                    'field' => '_js',
                    'secret' => self::SECRET,
                    'missing_score' => 15,
                ], $js),
            ],
        ]);
    }
}
