<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Integration\FormGuard;
use FormSpamChecker\Integration\WafGuard;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Waf\WafRequest;
use FormSpamChecker\Waf\WafVerdict;

/**
 * In-process tests of the two drop-in guards: configuration loading, request
 * matching and the response matrix (the reject() path terminates, so the
 * response is built by a separate, testable method).
 */
final class GuardDecisionsTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0';

    private function configDir(): string
    {
        $dir = $this->tempDir();
        $base = "'config' => ['storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]";

        file_put_contents($dir . '/off.php', "<?php return ['site' => 'off', 'mode' => 'off'];\n");
        file_put_contents($dir . '/shadow.php', "<?php return ['site' => 'shadow.example', 'mode' => 'shadow', "
            . "'form' => 'contact', 'response' => 'json', 'match' => ['#^/api/lead#'], 'skip' => ['#^/admin#'], {$base}];\n");
        file_put_contents($dir . '/block.php', "<?php return ['site' => 'block.example', 'mode' => 'enforce', "
            . "'form' => 'contact', 'response' => 'silent', 'match' => ['#^/api/lead#'], {$base}];\n");
        file_put_contents($dir . '/auto.php', "<?php return ['site' => 'auto.example', 'mode' => 'enforce', "
            . "'form' => 'contact', 'response' => 'auto', 'match' => [], 'skip' => [], {$base}];\n");
        file_put_contents($dir . '/waf_block.php', "<?php return ['site' => 'waf.example', 'mode' => 'enforce', 'form' => 'contact', "
            . "'match' => [], 'skip' => [], 'response' => 'auto', 'config' => ['waf' => ['enabled' => true, 'mode' => 'block'], "
            . "'storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]];\n");
        file_put_contents($dir . '/waf_shadow.php', "<?php return ['site' => 'wafshadow.example', 'mode' => 'enforce', 'form' => 'contact', "
            . "'match' => [], 'skip' => ['#^/admin#'], 'response' => 'json', 'config' => ['waf' => ['enabled' => true, 'mode' => 'monitor'], "
            . "'storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]];\n");
        file_put_contents($dir . '/broken.php', "<?php return 'not-an-array';\n");

        return $dir;
    }

    /**
     * @return array<string, mixed>
     */
    private function server(string $uri = '/api/lead', string $method = 'POST'): array
    {
        return ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => self::UA];
    }

    public function testFormGuardModesAndMatching(): void
    {
        $dir = $this->configDir();

        self::assertSame('off', FormGuard::boot('off', $dir)->mode());
        self::assertSame('shadow', FormGuard::boot('shadow', $dir)->mode());
        self::assertSame('enforce', FormGuard::boot('block', $dir)->mode());
        self::assertSame('off', FormGuard::boot('missing', $dir)->mode());

        $shadow = FormGuard::boot('shadow', $dir);
        self::assertSame('shadow.example', $shadow->site());
        self::assertSame('contact', $shadow->formId());
        self::assertSame('', $shadow->config()->string('response'));

        self::assertTrue($shadow->shouldHandle($this->server(), ['name' => 'x']));
        self::assertFalse($shadow->shouldHandle($this->server('/api/register'), ['name' => 'x']));
        self::assertFalse($shadow->shouldHandle($this->server('/admin/api/lead'), ['name' => 'x']));
        self::assertFalse($shadow->shouldHandle($this->server('/api/lead', 'GET'), ['name' => 'x']));
        self::assertFalse($shadow->shouldHandle($this->server(), []));
    }

    public function testFormGuardShadowNeverRejectsAndEnforceBuildsResponse(): void
    {
        $dir = $this->configDir();
        $shadow = FormGuard::boot('shadow', $dir);
        $spam = ['name' => 'bot', 'website' => 'filled'];

        self::assertFalse($shadow->run($this->server(), $spam));

        $block = FormGuard::boot('block', $dir);
        $verdict = $block->evaluate($this->server(), $spam);
        self::assertTrue($verdict->isSpam());

        $response = $block->buildResponse($verdict, $this->server());
        self::assertSame(200, $response['status']);
        self::assertSame('', $response['body']);
        self::assertSame('blocked', $response['headers']['X-Spam-Guard']);
    }

    public function testFormGuardResponseMatrix(): void
    {
        $dir = $this->configDir();
        $verdict = Verdict::spam();

        $json = FormGuard::boot('shadow', $dir)->buildResponse($verdict, $this->server());
        self::assertSame(400, $json['status']);
        self::assertStringContainsString('spam_detected', $json['body']);

        $auto = FormGuard::boot('auto', $dir)->buildResponse($verdict, ['HTTP_ACCEPT' => 'text/html', 'REQUEST_URI' => '/page']);
        self::assertStringContainsString('<!doctype html>', $auto['body']);

        $autoJson = FormGuard::boot('auto', $dir)->buildResponse($verdict, ['HTTP_ACCEPT' => 'application/json']);
        self::assertStringContainsString('spam_detected', $autoJson['body']);
    }

    public function testFormGuardEvaluateFor(): void
    {
        $verdict = FormGuard::evaluateFor('shadow', ['name' => 'Иван'], $this->server(), 'contact', $this->configDir());

        self::assertTrue($verdict->isClean());
    }

    public function testWafGuardModesAndInspection(): void
    {
        $dir = $this->configDir();
        $block = WafGuard::boot('waf_block', $dir);
        $shadow = WafGuard::boot('waf_shadow', $dir);
        $off = WafGuard::boot('off', $dir);

        self::assertTrue($block->enabled());
        self::assertSame('block', $block->mode());
        self::assertFalse($off->enabled());

        $request = new WafRequest('POST', '/api/lead', '203.0.113.9', 'name=Иван', 'application/x-www-form-urlencoded', 9, ['host' => 'example.ru', 'user-agent' => self::UA]);
        self::assertTrue($block->shouldInspect($request));

        $attack = new WafRequest('POST', '/api/lead', '203.0.113.9', 'message=<script>alert(1)</script>', 'application/x-www-form-urlencoded', 40, ['host' => 'example.ru', 'user-agent' => self::UA]);
        self::assertTrue($block->inspect($attack)->isBlocked());

        $benign = new WafRequest('POST', '/api/lead', '203.0.113.9', 'name=Иван', 'application/x-www-form-urlencoded', 9, ['host' => 'example.ru', 'user-agent' => self::UA]);
        self::assertFalse($block->inspect($benign)->isBlocked());
        self::assertTrue($shadow->enabled());
        self::assertSame('auto', $shadow->responseType());
    }

    public function testWafGuardBuildsResponses(): void
    {
        $dir = $this->configDir();
        $block = WafGuard::boot('waf_block', $dir);
        $verdict = new WafVerdict(true, 100, [], WafVerdict::STATUS_BLOCKED);
        $request = new WafRequest('GET', '/api/lead', '203.0.113.9', '', '', 0, ['accept' => 'application/json', 'host' => 'example.ru']);

        $json = $block->buildResponse($request, $verdict);
        self::assertSame(403, $json['status']);
        self::assertStringContainsString('waf_blocked', $json['body']);
        self::assertSame('blocked', $json['headers']['X-WAF']);

        $htmlRequest = new WafRequest('GET', '/page', '203.0.113.9', '', '', 0, ['accept' => 'text/html', 'host' => 'example.ru']);
        self::assertStringContainsString('<!doctype html>', $block->buildResponse($htmlRequest, $verdict)['body']);
    }

    public function testGuardsSurviveBrokenConfiguration(): void
    {
        $log = $this->tempDir() . '/error.log';
        $previous = ini_set('error_log', $log);

        try {
            $formMode = FormGuard::boot('broken', $this->configDir())->mode();
            $wafEnabled = WafGuard::boot('broken', $this->configDir())->enabled();
        } finally {
            ini_set('error_log', $previous === false ? '' : $previous);
        }

        self::assertSame('off', $formMode);
        self::assertFalse($wafEnabled);
        self::assertStringContainsString('must return an array', (string) @file_get_contents($log));
    }
}
