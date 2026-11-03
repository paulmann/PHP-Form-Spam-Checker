<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Behavioral;

use FormSpamChecker\Behavioral\JsChallenge;
use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Exception\InvalidConfigException;
use PHPUnit\Framework\TestCase;

final class JsChallengeTest extends TestCase
{
    private const SECRET = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';
    private const NOW = 1_800_000_000;

    public function testIssueReturnsSignedTokenAndChallenge(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        self::assertArrayHasKey('token', $issued);
        self::assertArrayHasKey('challenge', $issued);
        self::assertIsInt($issued['challenge']);
        self::assertGreaterThanOrEqual(1, $issued['challenge']);
        self::assertLessThanOrEqual(9, $issued['challenge']);
        self::assertCount(2, explode('.', $issued['token']));
    }

    public function testIssueIsDeterministicForChallengeButNotToken(): void
    {
        $challenge = new JsChallenge($this->config());
        $first = $challenge->issue('contact', self::NOW);
        $second = $challenge->issue('contact', self::NOW);

        self::assertSame($first['challenge'], $second['challenge']);
        self::assertNotSame($first['token'], $second['token']);
    }

    public function testExpectedAnswerFormula(): void
    {
        $challenge = new JsChallenge($this->config());

        self::assertSame('10', $challenge->expectedAnswer(1));
        self::assertSame('38', $challenge->expectedAnswer(5));
        self::assertSame('3', $challenge->expectedAnswer(0));
    }

    public function testVerifyAcceptsValidAnswer(): void
    {
        $challenge = new JsChallenge($this->config());
        $data = $this->validRequest($challenge);

        self::assertTrue($challenge->verify($data, 'contact'));
    }

    public function testVerifyRejectsWrongAnswer(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        $data = new RequestData([
            '_js' => '999',
            '_js_token' => $issued['token'],
        ], now: self::NOW);

        self::assertFalse($challenge->verify($data, 'contact'));
    }

    public function testVerifyRejectsMissingFields(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        self::assertFalse($challenge->verify(new RequestData([], now: self::NOW), 'contact'));
        self::assertFalse($challenge->verify(
            new RequestData(['_js' => $challenge->expectedAnswer($issued['challenge'])], now: self::NOW),
            'contact',
        ));
        self::assertFalse($challenge->verify(
            new RequestData(['_js_token' => $issued['token']], now: self::NOW),
            'contact',
        ));
    }

    public function testVerifyRejectsTamperedToken(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);
        $token = $issued['token'];
        $last = $token[\strlen($token) - 1];
        $token[\strlen($token) - 1] = $last === 'A' ? 'B' : 'A';

        $data = new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $token,
        ], now: self::NOW);

        self::assertFalse($challenge->verify($data, 'contact'));
    }

    public function testVerifyRejectsTokenForAnotherForm(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        $data = new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $issued['token'],
        ], now: self::NOW);

        self::assertFalse($challenge->verify($data, 'register'));
    }

    public function testVerifyRejectsExpiredToken(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        $data = new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $issued['token'],
        ], now: self::NOW + JsChallenge::DEFAULT_MAX_AGE + 1);

        self::assertFalse($challenge->verify($data, 'contact'));
    }

    public function testVerifyAllowsSmallClockSkew(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        $data = new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $issued['token'],
        ], now: self::NOW - 3);

        self::assertTrue($challenge->verify($data, 'contact'));
    }

    public function testVerifyRejectsFutureTokenBeyondSkew(): void
    {
        $challenge = new JsChallenge($this->config());
        $issued = $challenge->issue('contact', self::NOW);

        $data = new RequestData([
            '_js' => $challenge->expectedAnswer($issued['challenge']),
            '_js_token' => $issued['token'],
        ], now: self::NOW - 10);

        self::assertFalse($challenge->verify($data, 'contact'));
    }

    public function testFallsBackToTimeTrapSecret(): void
    {
        $challenge = new JsChallenge(new Config([
            'time_trap' => ['secret' => self::SECRET],
            'behavioral' => ['js_challenge' => ['enabled' => true]],
        ]));

        self::assertTrue($challenge->isConfigured());
        self::assertTrue($challenge->verify($this->validRequest($challenge), 'contact'));
    }

    public function testShortSecretIsReportedAndIssueThrows(): void
    {
        $challenge = new JsChallenge($this->config(['secret' => 'short']));

        self::assertFalse($challenge->isConfigured());
        self::assertNotNull($challenge->configError());
        self::assertStringContainsString('secret', (string) $challenge->configError());
        self::assertFalse($challenge->verify(new RequestData([], now: self::NOW), 'contact'));

        try {
            $issued = $challenge->issue('contact', self::NOW);
            self::fail('issue() must throw when the secret is too short, got ' . $issued['token']);
        } catch (InvalidConfigException $exception) {
            self::assertStringContainsString('secret', $exception->getMessage());
        }
    }

    public function testCustomFieldName(): void
    {
        $challenge = new JsChallenge($this->config(['field' => '_human']));
        $issued = $challenge->issue('contact', self::NOW);

        self::assertSame('_human', $challenge->field());
        self::assertSame('_human_token', $challenge->tokenField());

        $data = new RequestData([
            '_human' => $challenge->expectedAnswer($issued['challenge']),
            '_human_token' => $issued['token'],
        ], now: self::NOW);

        self::assertTrue($challenge->verify($data, 'contact'));
    }

    public function testInlineScriptIsStableAndSelfContained(): void
    {
        $challenge = new JsChallenge($this->config());
        $script = $challenge->inlineScript('contact');

        self::assertSame($script, $challenge->inlineScript('contact'));
        self::assertStringContainsString('<script>', $script);
        self::assertStringContainsString('data-fs-js', $script);
        self::assertStringContainsString('_js_token', $script);
        self::assertStringContainsString('atob', $script);
        self::assertStringContainsString('TextDecoder', $script);
        self::assertStringNotContainsString('http://', $script);
        self::assertStringNotContainsString('https://', $script);
        // sprintf()-based form renderers embed the markup: a bare "%" would be
        // read as a format specifier and break rendering.
        self::assertStringNotContainsString('%', $script);
        self::assertNotSame($script, $challenge->inlineScript('register'));
    }

    public function testInlineScriptHashMatchesScriptBody(): void
    {
        $challenge = new JsChallenge($this->config());
        $script = $challenge->inlineScript('contact');
        $hash = $challenge->inlineScriptHash('contact');

        $start = strpos($script, "<script>\n");
        self::assertNotFalse($start);
        $bodyStart = $start + \strlen("<script>\n");
        $bodyEnd = strrpos($script, "\n</script>");
        self::assertNotFalse($bodyEnd);

        $body = substr($script, $bodyStart, $bodyEnd - $bodyStart);

        self::assertSame('sha256-' . base64_encode(hash('sha256', $body, true)), $hash);
        self::assertSame($hash, $challenge->inlineScriptHash('contact'));
    }

    public function testInlineScriptCannotBreakOutOfScriptTag(): void
    {
        $script = (new JsChallenge($this->config()))->inlineScript('</script><script>alert(1)</script>');

        self::assertSame(1, substr_count($script, '</script>'));
        self::assertStringNotContainsString('<script>alert(1)', $script);
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

    private function validRequest(JsChallenge $challenge, string $formId = 'contact'): RequestData
    {
        $issued = $challenge->issue($formId, self::NOW);

        return new RequestData([
            $challenge->field() => $challenge->expectedAnswer($issued['challenge']),
            $challenge->tokenField() => $issued['token'],
        ], formId: $formId, now: self::NOW);
    }
}
