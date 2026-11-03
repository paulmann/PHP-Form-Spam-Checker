<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\XssRule;

final class XssRuleTest extends WafTestCase
{
    public function testScriptTagInAFieldIsAHardFinding(): void
    {
        $finding = (new XssRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => '<script>alert(1)</script>'],
        ));

        $this->assertHardFinding($finding, 'xss');
        self::assertSame(90, $finding->severity);
        self::assertSame('field.message', $finding->location);
    }

    public function testJavascriptUriInAQueryParameterIsDetected(): void
    {
        $finding = (new XssRule(new Config()))->inspect($this->request(
            uri: '/redirect',
            query: ['next' => 'javascript:alert(document.cookie)'],
        ));

        $this->assertHardFinding($finding, 'xss');
        self::assertSame('query.next', $finding->location);
    }

    public function testEventHandlerAttributeInACookieIsDetected(): void
    {
        $finding = (new XssRule(new Config()))->inspect($this->request(
            uri: '/account',
            cookies: ['pref' => 'x" onerror="alert(1)'],
        ));

        $this->assertHardFinding($finding, 'xss');
    }

    public function testXssInAJsonBodyIsDetected(): void
    {
        $finding = (new XssRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/api/lead',
            body: '{"comment":"<iframe src=//evil.example>"}',
            headers: ['content-type' => 'application/json'],
        ));

        $this->assertHardFinding($finding, 'xss');
        self::assertSame('body', $finding->location);
    }

    public function testOrdinaryProseAndMarkupAreNotFlagged(): void
    {
        $messages = [
            'Спасибо; ответьте, пожалуйста.',
            'The <b>bold</b> and <i>italic</i> tags are fine in a message.',
            'It\'s fine; quotes \' and " here.',
            'Entity &#60;script&#62; in text is not executable.',
            'См. https://example.ru/report?id=1',
        ];

        foreach ($messages as $message) {
            $finding = (new XssRule(new Config()))->inspect($this->request(
                method: 'POST',
                uri: '/contact',
                fields: ['message' => $message],
            ));

            self::assertNull($finding, 'false positive on: ' . mb_substr($message, 0, 60));
        }
    }

    public function testMultipartAndBinaryBodiesAreExcluded(): void
    {
        $multipart = $this->request(
            method: 'POST',
            uri: '/upload',
            body: "<script>alert(1)</script>",
            headers: ['content-type' => 'multipart/form-data; boundary=x'],
        );
        self::assertNull((new XssRule(new Config()))->inspect($multipart));

        $binary = $this->request(
            method: 'POST',
            uri: '/upload',
            body: "\x00<script>alert(1)</script>",
            headers: ['content-type' => 'application/octet-stream'],
        );
        self::assertNull((new XssRule(new Config()))->inspect($binary));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(method: 'POST', uri: '/contact', fields: ['message' => '<script>x</script>']);

        self::assertTrue((new XssRule(new Config()))->enabled());
        self::assertNull((new XssRule(new Config(['waf' => ['rules' => ['xss' => false]]])))->inspect($request));
        self::assertNull((new XssRule(new Config([
            'waf' => ['rules' => ['xss' => ['enabled' => false]]],
        ])))->inspect($request));
    }

    public function testSeverityAndHardnessAreConfigurable(): void
    {
        $finding = (new XssRule(new Config([
            'waf' => ['rules' => ['xss' => ['severity' => 45, 'hard' => false]]],
        ])))->inspect($this->request(method: 'POST', uri: '/contact', fields: ['message' => '<script>x</script>']));

        self::assertNotNull($finding);
        self::assertSame(45, $finding->severity);
        self::assertFalse($finding->hard);
    }
}
