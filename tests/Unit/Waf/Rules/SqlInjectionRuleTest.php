<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\SqlInjectionRule;

final class SqlInjectionRuleTest extends WafTestCase
{
    public function testUnionSelectInAFieldIsAHardFinding(): void
    {
        $finding = (new SqlInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => '1 UNION SELECT username FROM users'],
        ));

        $this->assertHardFinding($finding, 'sql_injection');
        self::assertSame(90, $finding->severity);
        self::assertSame('field.message', $finding->location);
    }

    public function testTautologyInAQueryParameterIsDetected(): void
    {
        $finding = (new SqlInjectionRule(new Config()))->inspect($this->request(
            uri: '/product',
            query: ['id' => "1' OR 1=1 --"],
        ));

        $this->assertHardFinding($finding, 'sql_injection');
        self::assertSame('query.id', $finding->location);
    }

    public function testSqlInACookieIsDetected(): void
    {
        $finding = (new SqlInjectionRule(new Config()))->inspect($this->request(
            uri: '/account',
            cookies: ['pref' => 'abc; DROP TABLE users; --'],
        ));

        $this->assertHardFinding($finding, 'sql_injection');
    }

    public function testSqlInAJsonBodyIsDetected(): void
    {
        $finding = (new SqlInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/api/lead',
            body: '{"query":"1 UNION SELECT 1"}',
            headers: ['content-type' => 'application/json'],
        ));

        $this->assertHardFinding($finding, 'sql_injection');
        self::assertSame('body', $finding->location);
    }

    public function testOrdinaryProseIsNotFlagged(): void
    {
        $messages = [
            'select the report from the list',
            'Спасибо; ответьте, пожалуйста.',
            'It\'s fine; quotes \' and " here.',
            'См. https://example.ru/report?id=1',
            str_repeat('Длинный текст заявки ', 500),
        ];

        foreach ($messages as $message) {
            $finding = (new SqlInjectionRule(new Config()))->inspect($this->request(
                method: 'POST',
                uri: '/contact',
                fields: ['message' => $message],
            ));

            self::assertNull($finding, 'false positive on: ' . mb_substr($message, 0, 60));
        }
    }

    public function testUrlWithIdParameterIsNotFlagged(): void
    {
        self::assertNull((new SqlInjectionRule(new Config()))->inspect($this->request(uri: '/product?id=1')));
    }

    public function testMultipartAndBinaryBodiesAreExcluded(): void
    {
        $multipart = $this->request(
            method: 'POST',
            uri: '/upload',
            body: "\x00 1 UNION SELECT username FROM users",
            headers: ['content-type' => 'multipart/form-data; boundary=x'],
        );
        self::assertNull((new SqlInjectionRule(new Config()))->inspect($multipart));

        $binary = $this->request(
            method: 'POST',
            uri: '/upload',
            body: "\xFF\xFE 1 UNION SELECT 1",
            headers: ['content-type' => 'application/octet-stream'],
        );
        self::assertNull((new SqlInjectionRule(new Config()))->inspect($binary));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(method: 'POST', uri: '/contact', fields: ['message' => '1 UNION SELECT 1']);

        self::assertTrue((new SqlInjectionRule(new Config()))->enabled());
        self::assertNull((new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => false]],
        ])))->inspect($request));
        self::assertNull((new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => ['enabled' => false]]]],
        )))->inspect($request));
    }

    public function testSeverityAndHardnessAreConfigurable(): void
    {
        $finding = (new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => ['severity' => 55, 'hard' => false]]],
        ])))->inspect($this->request(method: 'POST', uri: '/contact', fields: ['message' => '1 UNION SELECT 1']));

        self::assertNotNull($finding);
        self::assertSame(55, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testPatternsAndAllowlistAreConfigurable(): void
    {
        $unionRequest = $this->request(method: 'POST', uri: '/contact', fields: ['message' => '1 UNION SELECT 1']);

        $custom = new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => [
                'patterns' => ['#benign-marker#i'],
            ]]],
        ]));
        self::assertNull($custom->inspect($unionRequest));
        $this->assertHardFinding(
            $custom->inspect($this->request(method: 'POST', uri: '/contact', fields: ['message' => 'benign-marker'])),
            'sql_injection',
        );

        $extra = new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => [
                'extra_patterns' => ['#benign-marker#i'],
            ]]],
        ]));
        self::assertNotNull($extra->inspect($unionRequest));
        self::assertNotNull($extra->inspect(
            $this->request(method: 'POST', uri: '/contact', fields: ['message' => 'benign-marker']),
        ));

        $allowlisted = new SqlInjectionRule(new Config([
            'waf' => ['rules' => ['sql_injection' => [
                'allowlist' => ['#UNION SELECT 1#'],
            ]]],
        ]));
        self::assertNull($allowlisted->inspect($unionRequest));
    }
}
