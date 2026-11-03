<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Tests\Support\TempDirTestCase;

/**
 * Process-level tests for the auxiliary CLI bridges: Bayesian trainer and WAF.
 */
final class CliBridgesTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    public function testTrainerTrainsPersistsAndScores(): void
    {
        $dir = $this->tempDir();
        $ham = $dir . '/ham.txt';
        $spam = $dir . '/spam.txt';
        file_put_contents($ham, "нужен отчёт по протоколу испытаний\nпрошу подготовить протокол поверки\n");
        file_put_contents($spam, "casino bitcoin bonus\nviagra cialis pharmacy\n");
        $config = $dir . '/config.json';
        file_put_contents($config, json_encode([
            'cache' => ['driver' => 'file', 'path' => $dir],
            'bayes' => ['enabled' => true, 'min_documents' => 1, 'threshold' => 0.9],
        ], JSON_THROW_ON_ERROR));

        $train = $this->runBinary('spam-train', ['--config=' . $config, '--ham=' . $ham, '--spam=' . $spam]);
        self::assertSame(0, $train['code'], $train['stderr']);
        $trained = json_decode($train['stdout'], true);
        self::assertSame(2, $trained['trained']['ham']);
        self::assertTrue($trained['persisted']);

        $stats = $this->runBinary('spam-train', ['--config=' . $config, '--stats']);
        self::assertSame(0, $stats['code']);
        self::assertStringContainsString('"trained":true', $stats['stdout']);

        $verdict = $this->runBinary('spam-check', [
            '--config=' . $config,
            '--json=' . json_encode([
                'form' => 'contact',
                'fields' => ['message' => 'casino bitcoin bonus'],
                'context' => ['userAgent' => self::UA],
            ], JSON_THROW_ON_ERROR),
        ]);
        self::assertSame(2, $verdict['code'], $verdict['stderr']);
        self::assertSame('spam', json_decode($verdict['stdout'], true)['status']);
    }

    public function testWafCliAllowsBenignAndBlocksAttacks(): void
    {
        $dir = $this->tempDir();
        $config = $dir . '/config.json';
        file_put_contents($config, '{"waf":{"enabled":true,"mode":"block"}}');

        $benign = $this->runBinary('waf-check', [
            '--config=' . $config,
            '--json=' . json_encode([
                'method' => 'POST',
                'uri' => '/api/lead',
                'ip' => '203.0.113.1',
                'headers' => ['user-agent' => self::UA, 'host' => 'example.ru', 'content-type' => 'application/x-www-form-urlencoded'],
                'body' => 'name=Иван&message=Нужен отчёт',
            ], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
        ]);
        self::assertSame(0, $benign['code'], $benign['stderr']);
        self::assertFalse(json_decode($benign['stdout'], true)['blocked']);

        $sqli = $this->runBinary('waf-check', [
            '--config=' . $config,
            '--json=' . json_encode([
                'method' => 'GET',
                'uri' => '/search',
                'ip' => '203.0.113.2',
                'headers' => ['user-agent' => self::UA, 'host' => 'example.ru'],
                'query' => ['q' => '1 UNION SELECT password FROM users'],
            ], JSON_THROW_ON_ERROR),
        ]);
        self::assertSame(2, $sqli['code'], $sqli['stderr']);
        $decoded = json_decode($sqli['stdout'], true);
        self::assertTrue($decoded['blocked']);
        self::assertSame('blocked', $decoded['status']);

        $scanner = $this->runBinary('waf-check', [
            '--config=' . $config,
            '--json=' . json_encode([
                'method' => 'GET',
                'uri' => '/',
                'ip' => '203.0.113.3',
                'headers' => ['user-agent' => 'sqlmap/1.8', 'host' => 'example.ru'],
            ], JSON_THROW_ON_ERROR),
        ]);
        self::assertSame(2, $scanner['code']);
    }

    public function testWafCliDisabledConfigurationAllows(): void
    {
        $dir = $this->tempDir();
        $config = $dir . '/config.json';
        file_put_contents($config, '{"waf":{"enabled":false}}');

        $result = $this->runBinary('waf-check', [
            '--config=' . $config,
            '--json=' . '{"method":"GET","uri":"/","headers":{"user-agent":"sqlmap/1.8"}}',
        ]);

        self::assertSame(0, $result['code']);
        self::assertSame('disabled', json_decode($result['stdout'], true)['status']);
    }

    public function testWafCliInvalidPayloadExitsThree(): void
    {
        $result = $this->runBinary('waf-check', ['--json={broken']);

        self::assertSame(3, $result['code']);
    }

    /**
     * @param  list<string>                                     $args
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runBinary(string $binary, array $args): array
    {
        $root = \dirname(__DIR__, 2);
        $process = proc_open(
            [PHP_BINARY, $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . $binary, ...$args],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
        );

        self::assertIsResource($process, 'Cannot start bin/' . $binary);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['code' => proc_close($process), 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    }
}
