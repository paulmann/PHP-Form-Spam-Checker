<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\ProtocolRule;
use FormSpamChecker\Waf\WafRequest;

final class ProtocolRuleTest extends WafTestCase
{
    public function testDisallowedMethodIsAHardFinding(): void
    {
        $finding = (new ProtocolRule(new Config()))->inspect($this->request(method: 'TRACE', uri: '/contact'));

        $this->assertHardFinding($finding, 'protocol');
        self::assertSame(70, $finding->severity);
        self::assertSame('method', $finding->location);
        self::assertSame('TRACE', $finding->evidence['method']);
    }

    public function testOversizedDeclaredBodyIsHard(): void
    {
        $request = new WafRequest(
            method: 'POST',
            uri: '/upload',
            contentLength: 2_000_000,
            contentType: 'application/x-www-form-urlencoded',
            headers: ['host' => 'shop.example'],
        );

        $finding = (new ProtocolRule(new Config()))->inspect($request);

        $this->assertHardFinding($finding, 'protocol');
        self::assertSame('body', $finding->location);
        self::assertSame(1048576, $finding->evidence['max_body_bytes']);
    }

    public function testOversizedActualBodyIsHard(): void
    {
        $request = new WafRequest(
            method: 'POST',
            uri: '/upload',
            body: str_repeat('a', 1_100_000),
            contentType: 'application/x-www-form-urlencoded',
            headers: ['host' => 'shop.example'],
        );

        $this->assertHardFinding((new ProtocolRule(new Config()))->inspect($request), 'protocol');
    }

    public function testNegativeContentLengthIsHard(): void
    {
        $request = new WafRequest(
            method: 'POST',
            uri: '/upload',
            contentLength: -1,
            contentType: 'application/x-www-form-urlencoded',
            headers: ['host' => 'shop.example'],
        );

        $this->assertHardFinding((new ProtocolRule(new Config()))->inspect($request), 'protocol');
    }

    public function testUnexpectedContentTypeIsScoreOnlyByDefault(): void
    {
        $finding = (new ProtocolRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            body: 'x=1',
            headers: ['content-type' => 'application/x-custom'],
        ));

        self::assertNotNull($finding);
        self::assertSame('protocol', $finding->rule);
        self::assertSame('header.content-type', $finding->location);
        self::assertSame(40, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testContentTypeCanBeMadeHardByConfiguration(): void
    {
        $finding = (new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['content_type_hard' => true]]],
        ])))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            body: 'x=1',
            headers: ['content-type' => 'application/x-custom'],
        ));

        self::assertNotNull($finding);
        self::assertTrue($finding->hard);
    }

    public function testInvalidHostIsScoreOnlyByDefault(): void
    {
        $finding = (new ProtocolRule(new Config()))->inspect($this->request(headers: ['host' => 'bad host/evil']));

        self::assertNotNull($finding);
        self::assertSame('header.host', $finding->location);
        self::assertSame(50, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testMissingHostIsScoreOnlyByDefault(): void
    {
        $finding = (new ProtocolRule(new Config()))->inspect($this->request(headers: ['host' => '']));

        self::assertNotNull($finding);
        self::assertSame('header.host', $finding->location);
        self::assertSame(25, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testHostCanBeMadeHardByConfiguration(): void
    {
        $finding = (new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['host_hard' => true]]],
        ])))->inspect($this->request(headers: ['host' => 'bad host/evil']));

        self::assertNotNull($finding);
        self::assertTrue($finding->hard);
    }

    public function testWellFormedRequestsAreClean(): void
    {
        $rule = new ProtocolRule(new Config());

        self::assertNull($rule->inspect($this->request(uri: '/contact')));
        self::assertNull($rule->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            body: 'x=1',
            headers: ['content-type' => 'application/x-www-form-urlencoded'],
        )));
        self::assertNull($rule->inspect($this->request(
            method: 'POST',
            uri: '/api/lead',
            body: '{}',
            headers: ['content-type' => 'application/json; charset=utf-8'],
        )));
        self::assertNull($rule->inspect($this->request(method: 'OPTIONS', uri: '/contact')));
        self::assertNull($rule->inspect($this->request(method: 'DELETE', uri: '/contact')));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(method: 'TRACE', uri: '/contact');

        self::assertTrue((new ProtocolRule(new Config()))->enabled());

        $disabledFlag = new ProtocolRule(new Config(['waf' => ['rules' => ['protocol' => false]]]));
        self::assertNull($disabledFlag->inspect($request));

        self::assertNull((new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['enabled' => false]]],
        ])))->inspect($request));
    }

    public function testMaximumBodySizeIsConfigurable(): void
    {
        $rule = new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['max_body_bytes' => 10]]],
        ]));

        $request = new WafRequest(
            method: 'POST',
            uri: '/contact',
            body: '12345678901',
            contentType: 'application/x-www-form-urlencoded',
            headers: ['host' => 'shop.example'],
        );

        $this->assertHardFinding($rule->inspect($request), 'protocol');
    }

    public function testMethodAndContentTypeListsAreConfigurable(): void
    {
        $methodRule = new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['methods' => ['GET']]]],
        ]));

        $this->assertHardFinding($methodRule->inspect($this->request(method: 'POST', uri: '/contact')), 'protocol');

        $contentTypeRule = new ProtocolRule(new Config([
            'waf' => ['rules' => ['protocol' => ['content_types' => ['application/x-custom']]]],
        ]));

        self::assertNull($contentTypeRule->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            body: 'x=1',
            headers: ['content-type' => 'application/x-custom'],
        )));
    }
}
