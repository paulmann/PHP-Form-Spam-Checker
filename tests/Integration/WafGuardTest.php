<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Integration\WafGuard;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Waf\WafRequest;

/**
 * Tests of the drop-in HTTP firewall: configuration loading, the default skip
 * list, monitor/block modes and the terminate-on-block behaviour exercised
 * through a real PHP process.
 */
final class WafGuardTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private function configDir(): string
    {
        $dir = $this->tempDir();
        $storage = $dir . '/storage';
        $base = [
            'storage' => ['driver' => 'file', 'path' => $storage],
            'log' => ['enabled' => false],
            // The registry is covered by RejectedStoreTest; keep this suite free
            // of rejected-record files.
            'rejected' => ['enabled' => false],
        ];

        $website = [
            'site' => 'block.example',
            'waf_mode' => 'block',
            'config' => $base + ['waf' => $this->wafConfig()],
        ];
        $this->writeSite($dir, 'block', $website);

        $this->writeSite($dir, 'monitor', [
            'site' => 'monitor.example',
            'waf_mode' => 'monitor',
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'off', [
            'site' => 'off.example',
            'waf_mode' => 'off',
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'disabled', [
            'site' => 'disabled.example',
            'waf_mode' => 'block',
            'config' => $base + ['waf' => $this->wafConfig(['enabled' => false])],
        ]);

        $this->writeSite($dir, 'modeoverride', [
            'site' => 'override.example',
            'waf_mode' => 'block',
            'config' => $base + ['waf' => $this->wafConfig(['mode' => 'monitor'])],
        ]);

        $this->writeSite($dir, 'invalidmode', [
            'site' => 'invalid.example',
            'waf_mode' => 'banana',
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'customskip', [
            'site' => 'customskip.example',
            'waf_mode' => 'block',
            'waf_skip' => ['#^/custom-skip#'],
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'match', [
            'site' => 'match.example',
            'waf_mode' => 'block',
            'waf_match' => ['#^/api/#'],
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'json', [
            'site' => 'json.example',
            'waf_mode' => 'block',
            'waf_response' => 'json',
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'silent', [
            'site' => 'silent.example',
            'waf_mode' => 'block',
            'waf_response' => 'silent',
            'config' => $base + ['waf' => $this->wafConfig()],
        ]);

        $this->writeSite($dir, 'ratelimit', [
            'site' => 'ratelimit.example',
            'waf_mode' => 'block',
            'config' => $base + ['waf' => $this->wafConfig([
                'rules' => [
                    'sql_injection' => true,
                    'xss' => true,
                    'path_traversal' => true,
                    'command_injection' => true,
                    'scanner' => true,
                    'header_injection' => true,
                    'protocol' => true,
                    'ip_reputation' => false,
                    'rate_limit' => ['enabled' => true, 'max' => 1, 'window' => 60],
                ],
            ])],
        ]);

        file_put_contents($dir . '/broken.php', "<?php\n\nreturn 'not-an-array';\n");

        return $dir;
    }

    /**
     * @param array<string, mixed> $config
     */
    private function writeSite(string $dir, string $name, array $config): void
    {
        $code = '<?php' . "\n\n" . 'return ' . var_export($config, true) . ";\n";

        file_put_contents($dir . '/' . $name . '.php', $code);
    }

    /**
     * @param  array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function wafConfig(array $overrides = []): array
    {
        $config = [
            'enabled' => true,
            'mode' => 'monitor',
            'block_status' => 403,
            'rules' => [
                'sql_injection' => true,
                'xss' => true,
                'path_traversal' => true,
                'command_injection' => true,
                'scanner' => true,
                'header_injection' => true,
                'protocol' => true,
                'ip_reputation' => false,
                'rate_limit' => false,
            ],
        ];

        return array_replace($config, $overrides);
    }

    /**
     * @param  array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function server(string $uri = '/contact', string $method = 'GET', array $overrides = []): array
    {
        return $overrides + [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $uri,
            'REMOTE_ADDR' => '203.0.113.80',
            'HTTP_HOST' => 'block.example',
            'HTTP_USER_AGENT' => self::UA,
            'HTTP_ACCEPT' => 'text/html',
        ];
    }

    public function testBootReadsTheWafSectionFromTheSharedSiteFile(): void
    {
        $guard = WafGuard::boot('block', $this->configDir());

        self::assertSame('block.example', $guard->site());
        self::assertSame(WafGuard::MODE_BLOCK, $guard->mode());
        self::assertTrue($guard->enabled());
        self::assertTrue($guard->config()->bool('waf.enabled'));
    }

    public function testTopLevelWafModeOverridesTheNestedConfig(): void
    {
        $guard = WafGuard::boot('modeoverride', $this->configDir());

        self::assertSame(WafGuard::MODE_BLOCK, $guard->mode());
    }

    public function testInvalidModeFallsBackToOff(): void
    {
        $guard = WafGuard::boot('invalidmode', $this->configDir());

        self::assertSame(WafGuard::MODE_OFF, $guard->mode());
        self::assertFalse($guard->shouldInspect(new WafRequest(uri: '/.env', headers: ['host' => 'invalid.example'])));
    }

    public function testDisabledWafNeverInspects(): void
    {
        $guard = WafGuard::boot('disabled', $this->configDir());

        self::assertFalse($guard->enabled());
        self::assertFalse($guard->shouldInspect(new WafRequest(uri: '/.env', headers: ['host' => 'disabled.example'])));
    }

    public function testOffModeNeverInspects(): void
    {
        $guard = WafGuard::boot('off', $this->configDir());

        self::assertSame(WafGuard::MODE_OFF, $guard->mode());
        self::assertFalse($guard->shouldInspect(new WafRequest(uri: '/.env', headers: ['host' => 'off.example'])));
    }

    public function testDefaultSkipListProtectsAdministrativeAreas(): void
    {
        $guard = WafGuard::boot('block', $this->configDir());
        $headers = ['host' => 'block.example', 'user-agent' => self::UA];

        $skipUris = [
            '/wp-admin/options.php',
            '/bitrix/admin/index.php',
            '/admin/users',
            '/login',
            '/auth/callback',
            '/cpanel',
        ];

        foreach ($skipUris as $uri) {
            self::assertFalse(
                $guard->shouldInspect(new WafRequest(uri: $uri, headers: $headers)),
                $uri . ' must be skipped',
            );
        }

        self::assertTrue($guard->shouldInspect(new WafRequest(uri: '/contact', headers: $headers)));
    }

    public function testCustomSkipListReplacesTheDefaults(): void
    {
        $guard = WafGuard::boot('customskip', $this->configDir());
        $headers = ['host' => 'customskip.example', 'user-agent' => self::UA];

        self::assertFalse($guard->shouldInspect(new WafRequest(uri: '/custom-skip/page', headers: $headers)));
        self::assertTrue($guard->shouldInspect(new WafRequest(uri: '/admin/users', headers: $headers)));
    }

    public function testMatchListLimitsInspection(): void
    {
        $guard = WafGuard::boot('match', $this->configDir());
        $headers = ['host' => 'match.example', 'user-agent' => self::UA];

        self::assertTrue($guard->shouldInspect(new WafRequest(uri: '/api/lead', headers: $headers)));
        self::assertFalse($guard->shouldInspect(new WafRequest(uri: '/contact', headers: $headers)));
    }

    public function testBrokenConfigStaysOffAndLogsTheReason(): void
    {
        $logFile = $this->tempDir() . '/error.log';
        $previous = ini_set('error_log', $logFile);

        try {
            $guard = WafGuard::boot('broken', $this->configDir());
        } finally {
            ini_set('error_log', $previous === false ? '' : $previous);
        }

        self::assertSame(WafGuard::MODE_OFF, $guard->mode());
        self::assertFalse($guard->enabled());
        self::assertStringContainsString('must return an array', (string) @file_get_contents($logFile));
    }

    public function testConfigCachePicksUpModeChanges(): void
    {
        $dir = $this->tempDir();
        $file = $dir . '/cache.example.php';
        $mtime = 1_700_000_000;

        $write = static function (string $mode) use ($file, &$mtime): void {
            file_put_contents($file, "<?php\n\nreturn ['site' => 'cache.example', 'waf_mode' => '{$mode}'];\n");
            $mtime += 10;
            touch($file, $mtime);
        };

        $write('off');
        self::assertSame(WafGuard::MODE_OFF, WafGuard::boot('cache.example', $dir)->mode());

        $write('block');
        self::assertSame(WafGuard::MODE_BLOCK, WafGuard::boot('cache.example', $dir)->mode());
    }

    public function testBlockModeRejectsAScannerPathWithHtmlByDefault(): void
    {
        $result = $this->runGuard($this->configDir(), 'block', $this->server('/.env'));

        self::assertStringNotContainsString('PASSED', $result['stdout']);
        self::assertStringContainsString('<!doctype html', $result['stdout']);
        self::assertStringContainsString('защитой сайта', $result['stdout']);
        self::assertStringContainsString('[waf] blocked', $result['stderr']);
    }

    public function testBlockModePassesANormalRequest(): void
    {
        $result = $this->runGuard($this->configDir(), 'block', $this->server('/contact'));

        self::assertStringContainsString('PASSED', $result['stdout']);
        self::assertStringNotContainsString('<!doctype html', $result['stdout']);
    }

    public function testMonitorModeLogsButNeverRejects(): void
    {
        $result = $this->runGuard($this->configDir(), 'monitor', $this->server('/.env'));

        self::assertStringContainsString('PASSED', $result['stdout']);
        self::assertStringNotContainsString('<!doctype html', $result['stdout']);
        self::assertStringContainsString('[waf] verdict', $result['stderr']);
        self::assertStringContainsString('mode=monitor', $result['stderr']);
    }

    public function testJsonResponseIsChosenForJsonAccept(): void
    {
        $result = $this->runGuard(
            $this->configDir(),
            'block',
            $this->server('/.env', 'GET', ['HTTP_ACCEPT' => 'application/json']),
        );

        self::assertStringNotContainsString('PASSED', $result['stdout']);
        self::assertStringContainsString('"error":"waf_blocked"', $result['stdout']);
    }

    public function testJsonResponseIsChosenForApiUris(): void
    {
        $result = $this->runGuard(
            $this->configDir(),
            'block',
            $this->server('/api/lead', 'GET', ['HTTP_X_TEST' => "value\r\nInjected: 1"]),
        );

        self::assertStringNotContainsString('PASSED', $result['stdout']);
        self::assertStringContainsString('"ok":false', $result['stdout']);
        self::assertStringContainsString('"error":"waf_blocked"', $result['stdout']);
    }

    public function testExplicitJsonResponseConfiguration(): void
    {
        $result = $this->runGuard($this->configDir(), 'json', $this->server('/.env'));

        self::assertStringContainsString('"error":"waf_blocked"', $result['stdout']);
    }

    public function testSilentResponseProducesNoBody(): void
    {
        $result = $this->runGuard($this->configDir(), 'silent', $this->server('/.env'));

        self::assertSame('', trim($result['stdout']));
    }

    public function testSkipListProtectsTheAdminAreaInBlockMode(): void
    {
        $result = $this->runGuard($this->configDir(), 'block', $this->server('/wp-admin/options.php'));

        self::assertStringContainsString('PASSED', $result['stdout']);
    }

    public function testDisabledWafNeverBlocks(): void
    {
        $result = $this->runGuard($this->configDir(), 'disabled', $this->server('/.env'));

        self::assertStringContainsString('PASSED', $result['stdout']);
    }

    public function testOffModeNeverBlocks(): void
    {
        $result = $this->runGuard($this->configDir(), 'off', $this->server('/.env'));

        self::assertStringContainsString('PASSED', $result['stdout']);
    }

    public function testBrokenConfigFailsOpenInASubprocess(): void
    {
        $result = $this->runGuard($this->configDir(), 'broken', $this->server('/.env'));

        self::assertStringContainsString('PASSED', $result['stdout']);
        self::assertStringContainsString('must return an array', $result['stderr']);
    }

    public function testRateLimitBlocksRepeatedRequestsAndWritesOnlyToTheConfiguredStorage(): void
    {
        $root = \dirname(__DIR__, 2);
        $configDir = $this->configDir();
        $storageDir = $configDir . '/storage/waf';
        $outside = $root . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'waf';
        $outsideExisted = is_dir($outside);

        $first = $this->runGuard($configDir, 'ratelimit', $this->server('/contact'));
        self::assertStringContainsString('PASSED', $first['stdout']);

        $second = $this->runGuard($configDir, 'ratelimit', $this->server('/contact'));
        self::assertStringNotContainsString('PASSED', $second['stdout']);

        self::assertDirectoryExists($storageDir);
        $entries = glob($storageDir . '/*.json');
        self::assertIsArray($entries);
        self::assertNotSame([], $entries);

        if (!$outsideExisted) {
            self::assertDirectoryDoesNotExist($outside);
        }
    }

    public function testDropInEntryPointRunsWithTheDefaultConfiguration(): void
    {
        $root = \dirname(__DIR__, 2);
        $script = $this->tempDir() . '/drop-in-runner.php';
        $entryPoint = $root . DIRECTORY_SEPARATOR . 'integrations' . DIRECTORY_SEPARATOR . 'waf.php';
        file_put_contents($script, "<?php\n"
            . "\$_SERVER['HTTP_HOST'] = 'example.invalid';\n"
            . "\$_SERVER['REQUEST_METHOD'] = 'GET';\n"
            . "\$_SERVER['REQUEST_URI'] = '/.env';\n"
            . "\$_SERVER['REMOTE_ADDR'] = '203.0.113.81';\n"
            . 'require ' . var_export($entryPoint, true) . ";\n"
            . "echo 'PASSED';\n");

        $process = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root);
        self::assertIsResource($process);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        self::assertStringContainsString('PASSED', (string) $stdout);
        self::assertStringNotContainsString('<!doctype html', (string) $stdout);
        self::assertSame('', trim((string) $stderr));
    }

    /**
     * @param  array<string, mixed>                             $server
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runGuard(string $configDir, string $site, array $server, ?string $body = null): array
    {
        $root = \dirname(__DIR__, 2);
        $script = $this->tempDir() . '/waf-guard-runner.php';
        file_put_contents($script, "<?php\n"
            . "require " . var_export($root . DIRECTORY_SEPARATOR . 'autoload.php', true) . ";\n"
            . "\$guard = \\FormSpamChecker\\Integration\\WafGuard::boot(" . var_export($site, true)
            . ", " . var_export($configDir, true) . ");\n"
            . "\$guard->run(" . var_export($server, true) . ", null, null, null, " . var_export($body, true) . ");\n"
            . "echo 'PASSED';\n");

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

        return [
            'code' => proc_close($process),
            'stdout' => (string) $stdout,
            'stderr' => (string) $stderr,
        ];
    }
}
