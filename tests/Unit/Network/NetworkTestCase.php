<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Http\HttpResponse;
use PHPUnit\Framework\TestCase;

/**
 * Shared fixtures for the network-check tests: configuration builders, request
 * builders and an AbuseIPDB JSON body helper.
 */
abstract class NetworkTestCase extends TestCase
{
    protected const NOW = 1_700_000_000;

    /**
     * @param array<string, mixed> $overrides
     */
    protected function config(array $overrides = []): Config
    {
        return new Config($overrides);
    }

    /**
     * @param array<string, mixed> $fields
     */
    protected function request(string $ip = '203.0.113.9', array $fields = [], int $now = self::NOW): RequestData
    {
        return new RequestData(
            fields: $fields,
            ip: $ip,
            headers: [],
            cookies: [],
            query: [],
            method: 'POST',
            uri: '/contact',
            body: '',
            now: $now,
        );
    }

    /**
     * @param array<string, string> $headers
     */
    protected function response(int $status, string $body = '', array $headers = []): HttpResponse
    {
        return new HttpResponse($status, $headers, $body);
    }

    /**
     * AbuseIPDB configuration with the check enabled and a fake key.
     *
     * @param array<string, mixed> $overrides
     */
    protected function abuseConfig(array $overrides = []): Config
    {
        return $this->config(array_replace_recursive(
            ['abuseipdb' => ['enabled' => true, 'api_key' => 'test-key']],
            $overrides,
        ));
    }

    /**
     * @param array<string, mixed> $extra extra fields merged into data
     */
    protected function abuseBody(int $score, array $extra = []): string
    {
        $data = array_replace([
            'ipAddress' => '203.0.113.9',
            'isPublic' => true,
            'abuseConfidenceScore' => $score,
            'totalReports' => 42,
            'countryCode' => 'SE',
            'lastReportedAt' => '2024-01-02T03:04:05+00:00',
        ], $extra);

        return json_encode(['data' => $data], JSON_THROW_ON_ERROR);
    }
}
