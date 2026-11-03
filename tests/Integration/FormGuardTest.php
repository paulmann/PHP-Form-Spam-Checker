<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Integration\FormGuard;
use FormSpamChecker\Tests\Support\TempDirTestCase;

/**
 * Tests of the shared-module guard: request matching, modes, and the
 * terminate-on-spam behaviour exercised through a real PHP process.
 */
final class FormGuardTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private function configDir(): string
    {
        $dir = $this->tempDir();

        $baseConfig = <<<'PHP'
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
            ],
            PHP;

        file_put_contents($dir . '/off.php', "<?php return ['site' => 'off', 'mode' => 'off'];\n");

        file_put_contents($dir . '/shadow.php', "<?php return [\n"
            . "    'site' => 'shadow.example',\n"
            . "    'mode' => 'shadow',\n"
            . "    'form' => 'lead',\n"
            . "    'match' => ['#^/api/lead#'],\n"
            . "    'skip' => ['#^/admin#'],\n"
            . $baseConfig
            . "];\n");

        file_put_contents($dir . '/enforce.php', "<?php return [\n"
            . "    'site' => 'enforce.example',\n"
            . "    'mode' => 'enforce',\n"
            . "    'form' => 'support',\n"
            . "    'match' => ['#^/support/api\\.php#'],\n"
            . "    'skip' => ['#^/admin#'],\n"
            . "    'response' => 'json',\n"
            . $baseConfig
            . "];\n");

        file_put_contents($dir . '/silent.php', "<?php return [\n"
            . "    'site' => 'silent.example',\n"
            . "    'mode' => 'enforce',\n"
            . "    'form' => 'support',\n"
            . "    'match' => ['#^/support/api\\.php#'],\n"
            . "    'response' => 'silent',\n"
            . $baseConfig
            . "];\n");

        file_put_contents($dir . '/broken.php', "<?php return 'not-an-array';\n");

        return $dir;
    }

    /**
     * @return array<string, mixed>
     */
    private function server(string $method = 'POST', string $uri = '/api/lead'): array
    {
        return [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $uri,
            'REMOTE_ADDR' => '203.0.113.60',
            'HTTP_USER_AGENT' => self::UA,
            'HTTP_ACCEPT' => 'application/json',
        ];
    }

    public function testAutoFlagIsExposedInConfig(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/auto.example.php', "<?php return [\n"
            . "    'site' => 'auto.example',\n"
            . "    'mode' => 'shadow',\n"
            . "    'auto' => true,\n"
            . "    'config' => ['storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]],\n"
            . "];\n");

        $guard = FormGuard::boot('auto.example', $dir);

        self::assertTrue($guard->config()->bool('auto'));
        self::assertSame('shadow', $guard->mode());
    }

    public function testConfigCachePicksUpModifications(): void
    {
        $dir = $this->tempDir();
        $file = $dir . '/site.example.php';
        $mtime = 1_700_000_000;

        $write = static function (string $mode) use ($file, &$mtime): void {
            file_put_contents($file, "<?php return ['site' => 'site.example', 'mode' => '{$mode}'];\n");
            $mtime += 10;
            touch($file, $mtime);
        };

        $write('off');
        self::assertSame('off', FormGuard::boot('site.example', $dir)->mode());

        $write('enforce');
        self::assertSame('enforce', FormGuard::boot('site.example', $dir)->mode());
    }

    public function testOffModeNeverHandles(): void
    {
        $guard = FormGuard::boot('off', $this->configDir());

        self::assertSame('off', $guard->mode());
        self::assertFalse($guard->shouldHandle($this->server(), ['name' => 'x']));
    }

    public function testMissingConfigFallsBackToDefaultAndStaysOff(): void
    {
        $guard = FormGuard::boot('unknown.example', $this->configDir());

        self::assertSame('off', $guard->mode());
        self::assertFalse($guard->shouldHandle($this->server(), ['name' => 'x']));
    }

    public function testBrokenConfigStaysOff(): void
    {
        $logFile = $this->tempDir() . '/error.log';
        $previous = ini_set('error_log', $logFile);

        try {
            $guard = FormGuard::boot('broken', $this->configDir());
        } finally {
            ini_set('error_log', $previous === false ? '' : $previous);
        }

        self::assertSame('off', $guard->mode());
        self::assertStringContainsString('must return an array', (string) @file_get_contents($logFile));
    }

    public function testShadowModeMatchesOnlyConfiguredPostRequests(): void
    {
        $guard = FormGuard::boot('shadow', $this->configDir());

        self::assertTrue($guard->shouldHandle($this->server('POST', '/api/lead'), ['name' => 'x']));
        self::assertFalse($guard->shouldHandle($this->server('GET', '/api/lead'), ['name' => 'x']));
        self::assertFalse($guard->shouldHandle($this->server('POST', '/register/'), ['name' => 'x']));
        self::assertFalse($guard->shouldHandle($this->server('POST', '/api/lead'), []));
        self::assertFalse($guard->shouldHandle($this->server('POST', '/admin/api/lead'), ['name' => 'x']));
    }

    public function testShadowModeLogsButNeverRejects(): void
    {
        $guard = FormGuard::boot('shadow', $this->configDir());

        $rejected = $guard->run($this->server(), ['name' => 'bot', 'website' => 'filled']);

        self::assertFalse($rejected);
    }

    public function testEvaluateReturnsSpamVerdict(): void
    {
        $guard = FormGuard::boot('shadow', $this->configDir());

        $verdict = $guard->evaluate($this->server(), ['name' => 'bot', 'website' => 'filled']);

        self::assertTrue($verdict->isSpam());
    }

    public function testEvaluateForStaticHelper(): void
    {
        $verdict = FormGuard::evaluateFor(
            'shadow',
            ['name' => 'Иван', 'email' => 'ivan@example.com'],
            $this->server(),
            'lead',
            $this->configDir(),
        );

        self::assertTrue($verdict->isClean());
    }

    public function testEnforceModeBlocksSpamInChildProcess(): void
    {
        $result = $this->runGuardSubprocess('enforce', ['name' => 'bot', 'website' => 'filled']);

        self::assertStringContainsString('spam_detected', $result['stdout']);
        self::assertStringNotContainsString('PASSED', $result['stdout']);
    }

    public function testEnforceModePassesCleanSubmission(): void
    {
        $result = $this->runGuardSubprocess('enforce', [
            'name' => 'Иван Петров',
            'email' => 'ivan@example.com',
            'message' => 'Нужен отчёт за октябрь.',
        ]);

        self::assertStringContainsString('PASSED', $result['stdout']);
        self::assertStringNotContainsString('spam_detected', $result['stdout']);
    }

    public function testSilentResponseProducesNoBody(): void
    {
        $result = $this->runGuardSubprocess('silent', ['name' => 'bot', 'website' => 'filled']);

        self::assertSame('', trim($result['stdout']));
    }

    /**
     * @param  array<string, mixed>                             $fields
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runGuardSubprocess(string $site, array $fields): array
    {
        $root = \dirname(__DIR__, 2);
        $configDir = $this->configDir();

        $script = $this->tempDir() . '/guard-runner.php';
        $scriptCode = "<?php\n"
            . "require " . var_export($root . DIRECTORY_SEPARATOR . 'autoload.php', true) . ";\n"
            . "\$guard = FormSpamChecker\\Integration\\FormGuard::boot(" . var_export($site, true)
            . ", " . var_export($configDir, true) . ");\n"
            . "\$guard->run([\n"
            . "    'REQUEST_METHOD' => 'POST',\n"
            . "    'REQUEST_URI' => '/support/api.php',\n"
            . "    'REMOTE_ADDR' => '203.0.113.61',\n"
            . "    'HTTP_USER_AGENT' => " . var_export(self::UA, true) . ",\n"
            . "    'HTTP_ACCEPT' => 'application/json',\n"
            . "], " . var_export($fields, true) . ");\n"
            . "echo 'PASSED';\n";
        file_put_contents($script, $scriptCode);

        $process = proc_open(
            [PHP_BINARY, $script],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
        );

        self::assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['code' => proc_close($process), 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    }
}
