<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\HeaderInjectionRule;

final class HeaderInjectionRuleTest extends WafTestCase
{
    public function testCrlfInAHeaderValueIsAHardFinding(): void
    {
        $finding = (new HeaderInjectionRule(new Config()))->inspect($this->request(
            uri: '/contact',
            headers: ['x-test' => "value\r\nInjected: 1"],
        ));

        $this->assertHardFinding($finding, 'header_injection');
        self::assertSame(80, $finding->severity);
        self::assertSame('header.x-test', $finding->location);
    }

    public function testNulAndLfOnlyControlCharactersAreDetected(): void
    {
        $rule = new HeaderInjectionRule(new Config());

        $lf = $rule->inspect($this->request(headers: ['x-test' => "value\nnext"]));
        $nul = $rule->inspect($this->request(headers: ['x-test' => "value\0next"]));

        $this->assertHardFinding($lf, 'header_injection');
        $this->assertHardFinding($nul, 'header_injection');
    }

    public function testInvalidHeaderNameIsDetected(): void
    {
        $finding = (new HeaderInjectionRule(new Config()))->inspect($this->request(
            headers: ['bad header' => 'value'],
        ));

        $this->assertHardFinding($finding, 'header_injection');
        self::assertSame('header', $finding->location);
    }

    public function testCommaInHostIsADuplicateHeaderFinding(): void
    {
        $finding = (new HeaderInjectionRule(new Config()))->inspect($this->request(
            headers: ['host' => 'a.example, b.example'],
        ));

        $this->assertHardFinding($finding, 'header_injection');
        self::assertSame('header.host', $finding->location);
    }

    public function testCommaInContentLengthIsDetected(): void
    {
        $this->assertHardFinding(
            (new HeaderInjectionRule(new Config()))->inspect($this->request(headers: ['content-length' => '5, 7'])),
            'header_injection',
        );
    }

    public function testListValuedHeadersAreNotFlagged(): void
    {
        $finding = (new HeaderInjectionRule(new Config()))->inspect($this->request(headers: [
            'accept-language' => 'ru-RU,ru;q=0.9,en-US;q=0.8',
            'x-forwarded-for' => '198.51.100.1, 198.51.100.2',
            'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9',
        ]));

        self::assertNull($finding);
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(headers: ['x-test' => "a\r\nb"]);

        self::assertTrue((new HeaderInjectionRule(new Config()))->enabled());
        self::assertNull((new HeaderInjectionRule(new Config([
            'waf' => ['rules' => ['header_injection' => false]],
        ])))->inspect($request));
        self::assertNull((new HeaderInjectionRule(new Config(
            [
                'waf' => ['rules' => ['header_injection' => ['enabled' => false]]]],
        )))->inspect($request));
    }

    public function testSeverityIsConfigurable(): void
    {
        $finding = (new HeaderInjectionRule(new Config([
            'waf' => ['rules' => ['header_injection' => ['severity' => 50, 'hard' => false]]],
        ])))->inspect($this->request(headers: ['x-test' => "a\r\nb"]));

        self::assertNotNull($finding);
        self::assertSame(50, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testSingleValuedHeaderListIsConfigurable(): void
    {
        $rule = new HeaderInjectionRule(new Config([
            'waf' => ['rules' => ['header_injection' => ['single_valued_headers' => ['x-forwarded-for']]]],
        ]));

        $this->assertHardFinding(
            $rule->inspect($this->request(headers: ['x-forwarded-for' => '198.51.100.1, 198.51.100.2'])),
            'header_injection',
        );
    }
}
