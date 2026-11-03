<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Cache\ArrayCache;
use FormSpamChecker\Check\AbuseIpdbCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Http\HttpClientException;
use FormSpamChecker\Tests\Unit\Network\Fake\RecordingHttpClient;
use FormSpamChecker\Tests\Unit\Network\Fake\RecordingLogger;

final class AbuseIpdbCheckTest extends NetworkTestCase
{
    private RecordingHttpClient $http;

    private RecordingLogger $logger;

    private ArrayCache $cache;

    protected function setUp(): void
    {
        $this->http = new RecordingHttpClient();
        $this->logger = new RecordingLogger();
        $this->cache = new ArrayCache(self::NOW);
    }

    public function testDisabledCheckMakesNoNetworkCall(): void
    {
        $outcome = $this->check($this->config())->check($this->request());

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('disabled', $outcome->reason);
        self::assertSame(0, $this->http->callCount());
    }

    public function testMissingApiKeyIsUncertainWithoutNetworkCall(): void
    {
        $config = $this->config(['abuseipdb' => ['enabled' => true, 'api_key' => '']]);

        $outcome = $this->check($config)->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('API key', $outcome->reason);
        self::assertSame(0, $this->http->callCount());
    }

    public function testMissingAndInvalidIpAreUncertainWithoutNetworkCall(): void
    {
        $check = $this->check($this->abuseConfig());

        $missing = $check->check($this->request(ip: ''));
        $invalid = $check->check($this->request(ip: 'definitely-not-an-ip'));

        self::assertSame(CheckStatus::UNCERTAIN, $missing->status);
        self::assertSame(CheckStatus::UNCERTAIN, $invalid->status);
        self::assertSame(0, $this->http->callCount());
    }

    public function testPrivateIpIsNotQueried(): void
    {
        $outcome = $this->check($this->abuseConfig())->check($this->request(ip: '192.168.1.10'));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('private', $outcome->reason);
        self::assertSame('192.168.1.10', $outcome->evidence['ip']);
        self::assertSame(0, $this->http->callCount());
    }

    public function testScoreAtThresholdIsHardSpamWithEvidence(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(90)));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(90, $outcome->score);
        self::assertSame(90, $outcome->evidence['score']);
        self::assertSame(90, $outcome->evidence['threshold']);
        self::assertSame(42, $outcome->evidence['totalReports']);
        self::assertSame('SE', $outcome->evidence['countryCode']);
        self::assertSame('2024-01-02T03:04:05+00:00', $outcome->evidence['lastReportedAt']);
    }

    public function testScoreBelowThresholdIsHamWithEvidence(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(89)));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame(89, $outcome->evidence['score']);
        self::assertFalse($outcome->isFlagged());
    }

    public function testCustomThresholdIsApplied(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(60)));

        $config = $this->abuseConfig(['abuseipdb' => ['threshold' => 50]]);
        $outcome = $this->check($config)->check($this->request());

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(50, $outcome->evidence['threshold']);
    }

    public function testMalformedResponseFailsOpen(): void
    {
        $this->http->queue($this->response(200, 'not json at all'));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('malformed', $outcome->reason);
        self::assertTrue($this->logger->hasLevel('error'));
    }

    public function testMalformedResponseFailsClosedWhenFailOpenIsDisabled(): void
    {
        $this->http->queue($this->response(200, '{"unexpected":"shape"}'));
        $config = $this->abuseConfig(['abuseipdb' => ['fail_open' => false]]);

        $outcome = $this->check($config)->check($this->request());

        self::assertSame(CheckStatus::ERROR, $outcome->status);
    }

    public function testCachedAnswerSkipsTheSecondHttpCall(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(95)));

        $check = $this->check($this->abuseConfig(['abuseipdb' => ['cache_ttl' => 3600]]));
        $first = $check->check($this->request());
        $second = $check->check($this->request());

        self::assertSame(CheckStatus::SPAM, $second->status);
        self::assertSame($first->evidence, $second->evidence);
        self::assertSame(1, $this->http->callCount());
    }

    public function testCachedAnswerExpiresAfterTtl(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(10)));
        $this->http->queue($this->response(200, $this->abuseBody(99)));

        $check = $this->check($this->abuseConfig(['abuseipdb' => ['cache_ttl' => 3600]]));

        self::assertSame(CheckStatus::HAM, $check->check($this->request())->status);

        $this->cache->travel(3599);
        self::assertSame(CheckStatus::HAM, $check->check($this->request())->status);
        self::assertSame(1, $this->http->callCount());

        $this->cache->travel(2);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request())->status);
        self::assertSame(2, $this->http->callCount());
    }

    public function testRateLimitRetryAfterIsRespectedWithoutInProcessRetry(): void
    {
        $this->http->queue($this->response(429, '', ['retry-after' => '120']));

        $check = $this->check($this->abuseConfig());
        $limited = $check->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $limited->status);
        self::assertSame(self::NOW + 120, $limited->evidence['rate_limited_until']);
        self::assertTrue($this->logger->hasLevel('warning'));

        $stillLimited = $check->check($this->request());
        self::assertSame(CheckStatus::UNCERTAIN, $stillLimited->status);
        self::assertStringContainsString('still active', $stillLimited->reason);
        self::assertSame(1, $this->http->callCount());

        $this->http->queue($this->response(200, $this->abuseBody(0)));
        $afterBackoff = $check->check($this->request(now: self::NOW + 121));

        self::assertSame(CheckStatus::HAM, $afterBackoff->status);
        self::assertSame(2, $this->http->callCount());
    }

    public function testRateLimitResetHeaderIsConvertedToAbsoluteTimestamp(): void
    {
        $this->http->queue($this->response(429, '', ['x-ratelimit-reset' => (string) (self::NOW + 300)]));

        $check = $this->check($this->abuseConfig());
        $outcome = $check->check($this->request());

        self::assertSame(self::NOW + 300, $outcome->evidence['rate_limited_until']);

        $within = $check->check($this->request(now: self::NOW + 299));
        self::assertSame(CheckStatus::UNCERTAIN, $within->status);
        self::assertSame(1, $this->http->callCount());

        $this->http->queue($this->response(200, $this->abuseBody(0)));
        $after = $check->check($this->request(now: self::NOW + 300));

        self::assertSame(CheckStatus::HAM, $after->status);
        self::assertSame(2, $this->http->callCount());
    }

    public function testRateLimitWithoutHeadersFallsBackToDefaultBackoff(): void
    {
        $this->http->queue($this->response(429));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(self::NOW + 60, $outcome->evidence['rate_limited_until']);
    }

    public function testRetryAfterHttpDateIsRespected(): void
    {
        $retryAt = self::NOW + 90;
        $this->http->queue($this->response(429, '', ['retry-after' => gmdate('D, d M Y H:i:s', $retryAt) . ' GMT']));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame($retryAt, $outcome->evidence['rate_limited_until']);
    }

    public function testTransportExceptionFailsOpenByDefault(): void
    {
        $this->http->queue(new HttpClientException('connection refused'));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('transport error', $outcome->reason);
        self::assertTrue($this->logger->hasLevel('error'));
    }

    public function testTransportExceptionFailsClosedWhenFailOpenIsDisabled(): void
    {
        $this->http->queue(new HttpClientException('connection refused'));
        $config = $this->abuseConfig(['abuseipdb' => ['fail_open' => false]]);

        $outcome = $this->check($config)->check($this->request());

        self::assertSame(CheckStatus::ERROR, $outcome->status);
    }

    public function testServerErrorFailsOpenByDefault(): void
    {
        $this->http->queue($this->response(503));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('HTTP 503', $outcome->reason);
    }

    public function testServerErrorIsErrorWhenFailOpenIsDisabled(): void
    {
        $this->http->queue($this->response(500));
        $config = $this->abuseConfig(['abuseipdb' => ['fail_open' => false]]);

        $outcome = $this->check($config)->check($this->request());

        self::assertSame(CheckStatus::ERROR, $outcome->status);
    }

    public function testUnauthorizedResponseUsesTheFailOpenPolicy(): void
    {
        $this->http->queue($this->response(401));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('HTTP 401', $outcome->reason);
    }

    public function testCircuitBreakerOpensAfterConsecutiveTransportFailures(): void
    {
        $config = $this->abuseConfig([
            'abuseipdb' => ['circuit_breaker' => ['failures' => 2, 'cooldown' => 300]],
        ]);
        $check = $this->check($config);

        $this->http->queue(new HttpClientException('down'));
        self::assertSame(CheckStatus::UNCERTAIN, $check->check($this->request())->status);

        $this->http->queue(new HttpClientException('down'));
        self::assertSame(CheckStatus::UNCERTAIN, $check->check($this->request())->status);

        $open = $check->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $open->status);
        self::assertStringContainsString('circuit breaker', $open->reason);
        self::assertSame(2, $open->evidence['failures']);
        self::assertSame(self::NOW + 300, $open->evidence['open_until']);
        self::assertSame(2, $this->http->callCount());
    }

    public function testCircuitBreakerClosesAfterASuccessfulAttemptPastTheCooldown(): void
    {
        $config = $this->abuseConfig([
            'abuseipdb' => ['circuit_breaker' => ['failures' => 1, 'cooldown' => 60]],
        ]);
        $check = $this->check($config);

        $this->http->queue(new HttpClientException('down'));
        self::assertSame(CheckStatus::UNCERTAIN, $check->check($this->request())->status);

        $open = $check->check($this->request());
        self::assertStringContainsString('circuit breaker', $open->reason);
        self::assertSame(1, $this->http->callCount());

        $this->http->queue($this->response(200, $this->abuseBody(0)));
        $recovered = $check->check($this->request(now: self::NOW + 61));

        self::assertSame(CheckStatus::HAM, $recovered->status);
        self::assertSame(2, $this->http->callCount());

        // The breaker is closed again: one new failure does not short-circuit
        // the next attempt (the recording client answers from the queue). A fresh
        // IP keeps the per-IP answer cache out of the way.
        $this->http->queue(new HttpClientException('down'));
        $afterRecovery = $check->check($this->request(ip: '198.51.100.77', now: self::NOW + 62));

        self::assertSame(CheckStatus::UNCERTAIN, $afterRecovery->status);
        self::assertSame(3, $this->http->callCount());
    }

    public function testQuotaHeadersAreTrackedInEvidence(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(0), [
            'x-ratelimit-limit' => '1000',
            'x-ratelimit-remaining' => '999',
            'x-ratelimit-reset' => (string) (self::NOW + 30),
        ]));

        $outcome = $this->check($this->abuseConfig())->check($this->request());

        /** @var array<string, string> $quota */
        $quota = $outcome->evidence['quota'];
        self::assertSame('1000', $quota['x-ratelimit-limit']);
        self::assertSame('999', $quota['x-ratelimit-remaining']);
        self::assertSame((string) (self::NOW + 30), $quota['x-ratelimit-reset']);
    }

    public function testRequestShapeCarriesKeyAndQueryParameters(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(0)));

        $this->check($this->abuseConfig())->check($this->request(ip: '203.0.113.7'));

        $request = $this->http->requests[0];
        self::assertSame('GET', $request->method);
        self::assertSame(
            'https://api.abuseipdb.com/api/v2/check?ipAddress=203.0.113.7&maxAgeInDays=30',
            $request->url,
        );
        self::assertSame('test-key', $request->headers['Key']);
        self::assertSame('application/json', $request->headers['Accept']);
        self::assertEqualsWithDelta(2.0, $request->timeout, 0.0001);
    }

    public function testRequestRespectsConfiguredMaxAgeAndTimeout(): void
    {
        $this->http->queue($this->response(200, $this->abuseBody(0)));

        $config = $this->abuseConfig(['abuseipdb' => ['max_age_days' => 7, 'timeout' => 1.5]]);
        $this->check($config)->check($this->request(ip: '198.51.100.4'));

        $request = $this->http->requests[0];
        self::assertStringEndsWith('ipAddress=198.51.100.4&maxAgeInDays=7', $request->url);
        self::assertEqualsWithDelta(1.5, $request->timeout, 0.0001);
    }

    public function testFailedLookupIsNotCached(): void
    {
        $this->http->queue(new HttpClientException('down'));
        $check = $this->check($this->abuseConfig());

        self::assertSame(CheckStatus::UNCERTAIN, $check->check($this->request())->status);

        $this->http->queue($this->response(200, $this->abuseBody(99)));
        self::assertSame(CheckStatus::SPAM, $check->check($this->request())->status);
        self::assertSame(2, $this->http->callCount());
    }

    private function check(Config $config): AbuseIpdbCheck
    {
        return new AbuseIpdbCheck($this->http, $this->cache, $this->logger, $config);
    }
}
