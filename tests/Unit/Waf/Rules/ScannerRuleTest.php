<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\ScannerRule;

final class ScannerRuleTest extends WafTestCase
{
    public function testKnownScannerPathsAreHardFindings(): void
    {
        $uris = [
            '/.env',
            '/wp-login.php',
            '/phpmyadmin/index.php',
            '/cgi-bin/test.cgi',
            '/xmlrpc.php',
            '/wp-admin/options.php',
        ];

        foreach ($uris as $uri) {
            $finding = (new ScannerRule(new Config()))->inspect($this->request(uri: $uri));

            $this->assertHardFinding($finding, 'scanner');
            self::assertSame(80, $finding->severity);
            self::assertSame('uri', $finding->location);
        }
    }

    public function testScannerUserAgentsAreHardFindings(): void
    {
        $agents = [
            'sqlmap/1.7#stable (https://sqlmap.org)',
            'Mozilla/5.0 (compatible; Nikto/2.1.6)',
            'nuclei - open-source vulnerability scanner',
        ];

        foreach ($agents as $userAgent) {
            $finding = (new ScannerRule(new Config()))->inspect($this->request(
                uri: '/api/lead',
                headers: ['user-agent' => $userAgent],
            ));

            $this->assertHardFinding($finding, 'scanner');
            self::assertSame('header.user-agent', $finding->location);
            self::assertArrayHasKey('marker', $finding->evidence);
        }
    }

    public function testNormalRequestsAreNotFlagged(): void
    {
        $uris = ['/api/lead', '/contact', '/product?id=1', '/environment', '/wp-content/themes/site/style.css'];

        foreach ($uris as $uri) {
            self::assertNull((new ScannerRule(new Config()))->inspect($this->request(uri: $uri)), $uri);
        }
    }

    public function testBrowserUserAgentAndScannerWordInAFieldAreNotFlagged(): void
    {
        $request = $this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => 'sqlmap is a penetration-testing tool'],
        );

        self::assertNull((new ScannerRule(new Config()))->inspect($request));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(uri: '/.env');

        self::assertTrue((new ScannerRule(new Config()))->enabled());

        $disabledFlag = new ScannerRule(new Config(['waf' => ['rules' => ['scanner' => false]]]));
        self::assertNull($disabledFlag->inspect($request));

        self::assertNull((new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['enabled' => false]]],
        ])))->inspect($request));
    }

    public function testSeverityAndHardnessAreConfigurable(): void
    {
        $finding = (new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['severity' => 40, 'hard' => false]]],
        ])))->inspect($this->request(uri: '/.env'));

        self::assertNotNull($finding);
        self::assertSame(40, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testPathListsAreConfigurable(): void
    {
        $custom = new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['paths' => ['/secret-portal']]]],
        ]));

        $this->assertHardFinding($custom->inspect($this->request(uri: '/secret-portal/login')), 'scanner');
        self::assertNull($custom->inspect($this->request(uri: '/.env')));

        $extra = new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['extra_paths' => ['/extra-probe']]]],
        ]));

        $this->assertHardFinding($extra->inspect($this->request(uri: '/extra-probe/x')), 'scanner');
        $this->assertHardFinding($extra->inspect($this->request(uri: '/.env')), 'scanner');
    }

    public function testUserAgentListsAreConfigurable(): void
    {
        $custom = new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['user_agents' => ['my-scanner']]]],
        ]));

        $customHit = $this->request(uri: '/contact', headers: ['user-agent' => 'my-scanner/1.0']);
        $sqlmap = $this->request(uri: '/contact', headers: ['user-agent' => 'sqlmap/1.7']);

        $this->assertHardFinding($custom->inspect($customHit), 'scanner');
        self::assertNull($custom->inspect($sqlmap));

        $extra = new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['extra_user_agents' => ['my-scanner']]]],
        ]));

        $this->assertHardFinding($extra->inspect($customHit), 'scanner');
    }

    public function testAllowlistSkipsAMatchingPath(): void
    {
        $rule = new ScannerRule(new Config([
            'waf' => ['rules' => ['scanner' => ['allowlist' => ['#/\.env#']]]],
        ]));

        self::assertNull($rule->inspect($this->request(uri: '/.env')));
    }
}
