<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Tests\Support\TempDirTestCase;

/**
 * End-to-end tests of bin/spam-check: the process boundary that non-PHP
 * applications use in production.
 */
final class CliTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    public function testCleanPayloadExitsZero(): void
    {
        $payload = json_encode([
            'form' => 'contact',
            'fields' => ['name' => 'Иван', 'email' => 'ivan@example.ru', 'message' => 'Нужен отчёт.'],
            'context' => ['ip' => '203.0.113.1', 'userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE);

        $result = $this->runCli(['--json=' . $payload]);

        self::assertSame(0, $result['code'], $result['stderr']);
        $decoded = json_decode($result['stdout'], true);
        self::assertIsArray($decoded);
        self::assertSame('clean', $decoded['status']);
        self::assertSame('contact', $decoded['form']);
    }

    public function testSpamPayloadExitsTwo(): void
    {
        $payload = json_encode([
            'form' => 'contact',
            'fields' => ['name' => 'bot', 'email' => 'bot@example.ru', 'website' => 'filled'],
            'context' => ['ip' => '203.0.113.2', 'userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE);

        $result = $this->runCli(['--json=' . $payload]);

        self::assertSame(2, $result['code'], $result['stderr']);
        self::assertSame('spam', json_decode($result['stdout'], true)['status']);
    }

    public function testSuspiciousPayloadExitsOne(): void
    {
        $payload = json_encode([
            'form' => 'contact',
            'fields' => ['message' => 'казино, ставки на спорт, биткоин'],
            'context' => ['ip' => '203.0.113.3', 'userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE);

        $result = $this->runCli(['--json=' . $payload]);

        self::assertSame(1, $result['code'], $result['stderr']);
        self::assertSame('suspicious', json_decode($result['stdout'], true)['status']);
    }

    public function testBase64PositionalPayload(): void
    {
        $payload = json_encode(['fields' => ['name' => 'Иван'], 'context' => ['userAgent' => self::UA]]);
        $encoded = base64_encode((string) $payload);

        $result = $this->runCli([$encoded, '--form=contact']);

        self::assertSame(0, $result['code'], $result['stderr']);
        self::assertSame('contact', json_decode($result['stdout'], true)['form']);
    }

    public function testStdinPayload(): void
    {
        $payload = json_encode(['fields' => ['name' => 'Иван'], 'context' => ['userAgent' => self::UA]]);

        $result = $this->runCli(['--stdin'], (string) $payload);

        self::assertSame(0, $result['code'], $result['stderr']);
        self::assertSame('clean', json_decode($result['stdout'], true)['status']);
    }

    public function testSiteConfigurationFileIsAcceptedAndLogs(): void
    {
        $dir = $this->tempDir();
        $log = $dir . '/verdicts.jsonl';
        $configFile = $dir . '/site.php';
        $state = $dir . '/state';

        file_put_contents($configFile, "<?php return [\n"
            . "    'site' => 'example.ru',\n"
            . "    'mode' => 'enforce',\n"
            . "    'match' => ['#^/api/lead#'],\n"
            . "    'config' => [\n"
            . "        'storage' => ['driver' => 'file', 'path' => " . var_export($state, true) . "],\n"
            . "        'log' => ['enabled' => true, 'path' => " . var_export($log, true) . ", 'pii' => true],\n"
            . "    ],\n"
            . "];\n");

        $payload = json_encode([
            'form' => 'lead',
            'fields' => ['name' => 'bot', 'website' => 'filled'],
            'context' => ['ip' => '203.0.113.30', 'userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE);

        $result = $this->runCli(['--json=' . $payload, '--config=' . $configFile]);

        self::assertSame(2, $result['code'], $result['stderr']);
        self::assertFileExists($log);
        $lines = file($log, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        self::assertCount(1, $lines);
        $record = json_decode((string) $lines[0], true);
        self::assertSame('spam', $record['status']);
        self::assertSame('lead', $record['form']);
    }

    public function testCustomConfigFileIsApplied(): void
    {
        $config = $this->tempDir() . '/spam.php';
        file_put_contents($config, "<?php return ['thresholds' => ['suspicious' => 100, 'spam' => 100]];\n");

        $payload = json_encode([
            'fields' => ['message' => 'казино казино казино'],
            'context' => ['userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE);

        $result = $this->runCli(['--json=' . $payload, '--config=' . $config]);

        self::assertSame(0, $result['code'], $result['stderr']);
    }

    public function testInvalidJsonExitsThreeWithJsonError(): void
    {
        $result = $this->runCli(['--json={broken']);

        self::assertSame(3, $result['code']);
        $decoded = json_decode($result['stdout'], true);
        self::assertIsArray($decoded);
        self::assertSame('error', $decoded['status']);
    }

    public function testUnknownOptionExitsThree(): void
    {
        $result = $this->runCli(['--nope=1']);

        self::assertSame(3, $result['code']);
    }

    public function testHelpPrintsUsage(): void
    {
        $result = $this->runCli(['--help']);

        self::assertSame(0, $result['code']);
        self::assertStringContainsString('Usage: php bin/spam-check', $result['stderr']);
    }

    /**
     * @param list<string> $args
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runCli(array $args, string $stdin = ''): array
    {
        $root = dirname(__DIR__, 2);
        $command = [PHP_BINARY, $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'spam-check', ...$args];

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptors, $pipes, $root);

        self::assertIsResource($process, 'Cannot start bin/spam-check');

        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $code = proc_close($process);

        return ['code' => $code, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    }
}
