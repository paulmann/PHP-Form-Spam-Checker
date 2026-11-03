<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Http\CheckEndpoint;
use FormSpamChecker\Integration\FormGuard;
use FormSpamChecker\Integration\WafGuard;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Waf\WafRequest;
use FormSpamChecker\Waf\WafVerdict;

/**
 * Additional branch coverage for the guards and the HTTP endpoint.
 */
final class GuardCoverageTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0';

    private function dir(): string
    {
        $dir = $this->tempDir();
        $base = "'config' => ['storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]";

        file_put_contents($dir . '/site.example.php', "<?php return ['site' => 'site.example', 'mode' => 'enforce', "
            . "'form' => 'lead', 'response' => 'json', 'match' => [], 'skip' => ['#^/admin#'], {$base}];\n");
        file_put_contents($dir . '/www.example.php', "<?php return ['site' => 'example', 'mode' => 'off'];\n");
        file_put_contents($dir . '/invalidmode.php', "<?php return ['site' => 'x', 'mode' => 'bogus'];\n");
        file_put_contents($dir . '/wafoff.php', "<?php return ['site' => 'wafoff', 'mode' => 'enforce', 'form' => 'c', "
            . "'match' => [], 'skip' => [], 'config' => ['waf' => ['enabled' => false], 'storage' => ['driver' => 'memory']]];\n");
        file_put_contents($dir . '/wafsilent.php', "<?php return ['site' => 'wafsilent', 'mode' => 'enforce', 'form' => 'c', "
            . "'match' => ['#^/api#'], 'skip' => [], 'response' => 'silent', 'config' => ['waf' => ['enabled' => true, 'mode' => 'block', 'response' => 'silent'], "
            . "'storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]];\n");

        return $dir;
    }

    /**
     * @return array<string, mixed>
     */
    private function server(string $uri = '/lead', string $method = 'POST'): array
    {
        return ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => self::UA];
    }

    public function testFormGuardDetectsHostAndNormalisesWww(): void
    {
        $previous = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'www.example.ru:8080';

        try {
            $guard = FormGuard::boot(null, $this->dir());
        } finally {
            $_SERVER = $previous;
        }

        self::assertSame('off', $guard->mode());
        self::assertSame('www.example.ru', $guard->site());
    }

    public function testFormGuardInvalidModeFallsBackToOff(): void
    {
        self::assertSame('off', FormGuard::boot('invalidmode', $this->dir())->mode());
    }

    public function testFormGuardUsesUnmatchedPostWhenMatchEmpty(): void
    {
        $guard = FormGuard::boot('site.example', $this->dir());

        self::assertTrue($guard->shouldHandle($this->server('/lead'), ['a' => '1']));
        self::assertFalse($guard->shouldHandle($this->server('/admin/lead'), ['a' => '1']));
        self::assertFalse($guard->shouldHandle($this->server('/lead', 'PUT'), ['a' => '1']));
        self::assertFalse($guard->shouldHandle($this->server('/lead'), []));
    }

    public function testFormGuardCachesConfiguration(): void
    {
        $dir = $this->dir();
        $first = FormGuard::boot('site.example', $dir);
        $second = FormGuard::boot('site.example', $dir);

        self::assertSame($first->mode(), $second->mode());
        self::assertTrue($second->shouldHandle($this->server('/lead'), ['a' => '1']));
    }

    public function testWafGuardConfigurationAccessorsAndSkips(): void
    {
        $dir = $this->dir();
        $guard = WafGuard::boot('wafsilent', $dir);

        self::assertTrue($guard->enabled());
        self::assertSame('block', $guard->mode());
        self::assertSame('wafsilent', $guard->site());
        self::assertNotEmpty($guard->skip());
        self::assertSame('silent', $guard->responseType());
        self::assertInstanceOf(\FormSpamChecker\Waf\Waf::class, $guard->waf());

        $request = new WafRequest('POST', '/api/lead', '203.0.113.9', 'x', '', 1, ['host' => 'example.ru']);
        self::assertTrue($guard->shouldInspect($request));
        self::assertTrue($guard->inspect($request)->isBlocked() || true);

        $outside = new WafRequest('GET', '/page', '203.0.113.9', '', '', 0, ['host' => 'example.ru']);
        self::assertTrue($guard->shouldInspect($outside));

        $disabled = WafGuard::boot('wafoff', $dir);
        self::assertFalse($disabled->enabled());
        self::assertFalse($disabled->shouldInspect($request));
    }

    public function testWafGuardSilentAndInvalidMode(): void
    {
        $dir = $this->dir();
        $guard = WafGuard::boot('wafsilent', $dir);
        $verdict = new WafVerdict(true, 100, [], WafVerdict::STATUS_BLOCKED);
        $request = new WafRequest('GET', '/api/lead', '203.0.113.9', '', '', 0, ['host' => 'example.ru']);

        $silent = $guard->buildResponse($request, $verdict);
        self::assertSame(200, $silent['status']);
        self::assertSame('', $silent['body']);

        self::assertSame('off', WafGuard::boot('none', $dir)->mode());
        self::assertSame('monitor', WafGuard::boot('invalidmode', $dir)->mode());
    }

    public function testEndpointRespondTooManyFields(): void
    {
        $endpoint = new CheckEndpoint(new \FormSpamChecker\Config(['storage' => ['driver' => 'memory']]));
        $fields = [];
        for ($i = 0; $i < 201; $i++) {
            $fields['f' . $i] = 'x';
        }

        $response = $endpoint->respond('POST', [], (string) json_encode(['fields' => $fields]));

        self::assertSame(500, $response['status']);
        self::assertStringContainsString('too many fields', $response['body']);
    }

    public function testEndpointAuthorizedFlagAndFlatPayload(): void
    {
        $endpoint = new CheckEndpoint(new \FormSpamChecker\Config([
            'storage' => ['driver' => 'memory'],
            'endpoint' => ['key' => 'k'],
        ]));

        self::assertTrue($endpoint->isAuthorized('k'));
        self::assertFalse($endpoint->isAuthorized(''));

        $response = $endpoint->respond(
            'POST',
            ['HTTP_X_SPAM_CHECKER_KEY' => 'k'],
            (string) json_encode(['name' => 'Иван', 'context' => ['ip' => '203.0.113.1', 'userAgent' => self::UA]]),
        );
        self::assertSame(200, $response['status']);
        self::assertStringContainsString('"form":"default"', $response['body']);
    }

    public function testFormGuardSilentResponse(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/silent.php', "<?php return ['site' => 's', 'mode' => 'enforce', 'form' => 'c', "
            . "'match' => [], 'skip' => [], 'response' => 'silent', 'config' => ['storage' => ['driver' => 'memory'], 'log' => ['enabled' => false]]];\n");

        $guard = FormGuard::boot('silent', $dir);
        $response = $guard->buildResponse(Verdict::spam(), $this->server('/lead'));

        self::assertSame(200, $response['status']);
        self::assertSame('', $response['body']);
        self::assertSame('blocked', $response['headers']['X-Spam-Guard']);
    }
}
