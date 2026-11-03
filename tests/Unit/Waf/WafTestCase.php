<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf;

use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;
use PHPUnit\Framework\TestCase;

/**
 * Base class for WAF unit tests: builds request snapshots with realistic
 * defaults (host, browser User-Agent, form Content-Type) so a test only states
 * what it actually varies.
 */
abstract class WafTestCase extends TestCase
{
    public const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    /**
     * @var array<string, string>
     */
    protected const array DEFAULT_HEADERS = [
        'host' => 'shop.example',
        'user-agent' => self::UA,
        'content-type' => 'application/x-www-form-urlencoded',
        'accept' => 'text/html,application/xhtml+xml',
    ];

    /**
     * @param array<string, mixed>  $fields
     * @param array<string, string> $headers
     * @param array<string, mixed>  $query
     * @param array<string, string> $cookies
     */
    protected function request(
        string $method = 'GET',
        string $uri = '/',
        array $fields = [],
        string $body = '',
        array $headers = [],
        array $query = [],
        array $cookies = [],
        string $ip = '203.0.113.10',
        ?int $now = null,
    ): WafRequest {
        $headers += self::DEFAULT_HEADERS;

        return new WafRequest(
            method: $method,
            uri: $uri,
            ip: $ip,
            body: $body,
            contentType: $headers['content-type'],
            contentLength: strlen($body),
            headers: $headers,
            cookies: $cookies,
            query: $query,
            fields: $fields,
            now: $now,
        );
    }

    /**
     * @phpstan-assert WafFinding $finding
     */
    protected function assertHardFinding(?WafFinding $finding, string $rule): void
    {
        self::assertNotNull($finding, sprintf('expected rule "%s" to find something', $rule));
        self::assertSame($rule, $finding->rule);
        self::assertTrue($finding->hard, sprintf('expected rule "%s" to report a hard finding', $rule));
        self::assertGreaterThan(0, $finding->severity);
    }
}
