<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\PathTraversalRule;

final class PathTraversalRuleTest extends WafTestCase
{
    public function testTraversalInAFieldIsAHardFinding(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/download',
            fields: ['file' => '../../etc/passwd'],
        ));

        $this->assertHardFinding($finding, 'path_traversal');
        self::assertSame(85, $finding->severity);
        self::assertSame('field.file', $finding->location);
    }

    public function testEncodedTraversalInTheQueryIsDecodedBeforeMatching(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            uri: '/download?file=..%2f..%2fetc%2fpasswd',
        ));

        $this->assertHardFinding($finding, 'path_traversal');
        self::assertSame('uri', $finding->location);
    }

    public function testDoubleEncodedTraversalIsDetected(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/download',
            fields: ['file' => '%252e%252e%252fetc%252fpasswd'],
        ));

        $this->assertHardFinding($finding, 'path_traversal');
    }

    public function testWindowsTraversalIsDetected(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/download',
            fields: ['file' => '..\\windows\\win.ini'],
        ));

        $this->assertHardFinding($finding, 'path_traversal');
    }

    public function testCollapsedTraversalIsDetected(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/download',
            fields: ['file' => '....//etc/passwd'],
        ));

        $this->assertHardFinding($finding, 'path_traversal');
    }

    public function testAbsoluteFileProbeInTheQueryIsDetected(): void
    {
        $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
            uri: '/download',
            query: ['file' => '/etc/passwd'],
        ));

        $this->assertHardFinding($finding, 'path_traversal');
        self::assertSame('query.file', $finding->location);
    }

    public function testOrdinaryProseIsNotFlagged(): void
    {
        $messages = [
            'Смотрите... дальше в приложении.',
            'select the report from the list',
            'Спасибо; ответьте, пожалуйста.',
            'См. https://example.ru/report?id=1',
            // A technician may mention an absolute path in a message: file
            // probes are only applied to the request line, not to form text.
            'Проверьте права на /etc/hosts',
            str_repeat('Длинный текст заявки ', 500),
        ];

        foreach ($messages as $message) {
            $finding = (new PathTraversalRule(new Config()))->inspect($this->request(
                method: 'POST',
                uri: '/contact',
                fields: ['message' => $message],
            ));

            self::assertNull($finding, 'false positive on: ' . mb_substr($message, 0, 60));
        }
    }

    public function testUrlWithIdParameterIsNotFlagged(): void
    {
        self::assertNull((new PathTraversalRule(new Config()))->inspect($this->request(uri: '/product?id=1')));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(method: 'POST', uri: '/download', fields: ['file' => '../../etc/passwd']);

        self::assertTrue((new PathTraversalRule(new Config()))->enabled());
        self::assertNull((new PathTraversalRule(new Config([
            'waf' => ['rules' => ['path_traversal' => false]],
        ])))->inspect($request));
        self::assertNull((new PathTraversalRule(new Config(
            [
                'waf' => ['rules' => ['path_traversal' => ['enabled' => false]]]],
        )))->inspect($request));
    }

    public function testSeverityIsConfigurable(): void
    {
        $finding = (new PathTraversalRule(new Config([
            'waf' => ['rules' => ['path_traversal' => ['severity' => 60, 'hard' => false]]],
        ])))->inspect($this->request(method: 'POST', uri: '/download', fields: ['file' => '../x']));

        self::assertNotNull($finding);
        self::assertSame(60, $finding->severity);
        self::assertFalse($finding->hard);
    }

    public function testPatternsAreConfigurable(): void
    {
        $custom = new PathTraversalRule(new Config([
            'waf' => ['rules' => ['path_traversal' => ['patterns' => ['#traverse-me#i']]]],
        ]));

        $traversal = $this->request(method: 'POST', uri: '/download', fields: ['file' => '../../etc/passwd']);
        $customHit = $this->request(method: 'POST', uri: '/download', fields: ['file' => 'traverse-me']);

        self::assertNull($custom->inspect($traversal));
        self::assertNotNull($custom->inspect($customHit));
    }
}
