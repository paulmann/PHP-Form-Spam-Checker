<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Cache\CacheInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Http\HttpClientException;
use FormSpamChecker\Http\HttpClientInterface;
use FormSpamChecker\Http\HttpRequest;
use FormSpamChecker\Http\HttpResponse;
use FormSpamChecker\Log\LoggerInterface;
use JsonException;

/**
 * IP reputation through the AbuseIPDB v2 `check` endpoint.
 *
 * Semantics (see docs/ARCHITECTURE-V2.md):
 *
 * - disabled check, missing API key, missing/invalid IP: no network at all;
 *   `HAM`/`UNCERTAIN` contribute nothing to the score;
 * - definitive answers (`HAM`/`SPAM`) are cached under `abuseipdb:<ip>` for
 *   `abuseipdb.cache_ttl` seconds, so a burst of submissions costs one query;
 * - `HTTP 429` is never retried in-process: `Retry-After` / `X-RateLimit-Reset`
 *   are converted to an absolute timestamp, stored in the cache and every
 *   further lookup before that timestamp returns `UNCERTAIN` without network;
 * - transport errors (exception, `HTTP 5xx`) are "consecutive failures" for the
 *   circuit breaker: after `abuseipdb.circuit_breaker.failures` of them in a row
 *   the breaker opens for `cooldown` seconds, during which lookups fail fast
 *   with `UNCERTAIN`; the first successful HTTP response closes it again;
 * - `abuseipdb.fail_open = true` (default) turns a failed lookup into
 *   `UNCERTAIN`; with `false` the check reports `ERROR`.
 *
 * The clock comes from `RequestData::timestamp()` (`now`), never from `time()`,
 * which keeps the cache, rate-limit and breaker behaviour deterministic in tests.
 */
final readonly class AbuseIpdbCheck implements SpamCheckInterface
{
    private const ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
    private const CACHE_PREFIX = 'abuseipdb:';
    private const CIRCUIT_KEY = 'abuseipdb:circuit';
    private const RATE_LIMIT_KEY = 'abuseipdb:rate-limit';
    private const DEFAULT_RETRY_AFTER = 60;

    public function __construct(
        private HttpClientInterface $http,
        private CacheInterface $cache,
        private LoggerInterface $logger,
        private Config $config,
    ) {}

    public function name(): string
    {
        return 'abuseipdb';
    }

    public function check(RequestData $data): CheckOutcome
    {
        $check = $this->name();

        if (!$this->config->bool('abuseipdb.enabled', false)) {
            return CheckOutcome::ham($check, 'disabled');
        }

        $ip = $data->ip;
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return CheckOutcome::uncertain($check, 'no valid IP address in the request');
        }

        if (!$this->isPublicAddress($ip)) {
            return CheckOutcome::uncertain(
                $check,
                'IP address is private, reserved or loopback: AbuseIPDB is not queried',
                ['ip' => $ip],
            );
        }

        if ($this->config->string('abuseipdb.api_key') === '') {
            return CheckOutcome::uncertain($check, 'AbuseIPDB API key is not configured');
        }

        $now = $data->timestamp();

        $cached = $this->cachedOutcome($this->cache->get(self::CACHE_PREFIX . $ip));
        if ($cached !== null) {
            return $cached;
        }

        $rateLimitedUntil = $this->rateLimitedUntil();
        if ($rateLimitedUntil > $now) {
            return CheckOutcome::uncertain(
                $check,
                \sprintf('AbuseIPDB rate limit is still active for %d second(s)', $rateLimitedUntil - $now),
                ['ip' => $ip, 'rate_limited_until' => $rateLimitedUntil],
            );
        }

        $circuit = $this->circuitState();
        if ($circuit['open_until'] > $now) {
            $this->logger->warning('AbuseIPDB circuit breaker is open; lookup skipped', [
                'ip' => $ip,
                'retry_in' => $circuit['open_until'] - $now,
            ]);

            return CheckOutcome::uncertain($check, 'AbuseIPDB circuit breaker is open', [
                'ip' => $ip,
                'failures' => $circuit['failures'],
                'open_until' => $circuit['open_until'],
            ]);
        }

        try {
            $response = $this->http->send($this->buildRequest($ip));
        } catch (HttpClientException $exception) {
            return $this->onTransportFailure($ip, $now, 'transport error: ' . $exception->getMessage());
        }

        if ($response->status === 429) {
            return $this->handleRateLimited($ip, $now, $response);
        }

        if ($response->status >= 500) {
            return $this->onTransportFailure($ip, $now, 'HTTP ' . $response->status);
        }

        if ($response->status !== 200) {
            // Any non-5xx response proves the server is reachable: keep the breaker closed.
            $this->resetCircuit();

            return $this->failureOutcome($ip, 'HTTP ' . $response->status);
        }

        $this->resetCircuit();

        return $this->handleSuccess($ip, $response);
    }

    private function isPublicAddress(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private function buildRequest(string $ip): HttpRequest
    {
        $maxAgeDays = max(0, $this->config->int('abuseipdb.max_age_days', 30));

        return new HttpRequest(
            method: 'GET',
            url: self::ENDPOINT . '?ipAddress=' . rawurlencode($ip) . '&maxAgeInDays=' . $maxAgeDays,
            headers: [
                'Key' => $this->config->string('abuseipdb.api_key'),
                'Accept' => 'application/json',
            ],
            timeout: max(0.1, $this->config->float('abuseipdb.timeout', 2.0)),
        );
    }

    private function handleSuccess(string $ip, HttpResponse $response): CheckOutcome
    {
        $payload = $this->decodePayload($response->body);
        $block = \is_array($payload) && isset($payload['data']) && \is_array($payload['data']) ? $payload['data'] : null;
        $score = $block === null ? null : ($block['abuseConfidenceScore'] ?? null);

        if ($block === null || !\is_int($score)) {
            return $this->failureOutcome($ip, 'malformed AbuseIPDB response');
        }

        $threshold = $this->config->int('abuseipdb.threshold', 90);

        $evidence = ['ip' => $ip, 'score' => $score, 'threshold' => $threshold];
        foreach (['totalReports', 'countryCode', 'countryName', 'lastReportedAt'] as $key) {
            if (\array_key_exists($key, $block)) {
                $evidence[$key] = $block[$key];
            }
        }

        $quota = $this->quotaHeaders($response);
        if ($quota !== []) {
            $evidence['quota'] = $quota;
        }

        $outcome = $score >= $threshold
            ? CheckOutcome::spam(
                $this->name(),
                \sprintf('abuse confidence score %d is at or above the threshold %d', $score, $threshold),
                $evidence,
                $score,
            )
            : new CheckOutcome(
                $this->name(),
                CheckStatus::HAM,
                0,
                \sprintf('abuse confidence score %d is below the threshold %d', $score, $threshold),
                $evidence,
            );

        $this->cache->set(self::CACHE_PREFIX . $ip, [
            'status' => $outcome->status->value,
            'score' => $outcome->score,
            'reason' => $outcome->reason,
            'evidence' => $outcome->evidence,
        ], $this->config->int('abuseipdb.cache_ttl', 21600));

        return $outcome;
    }

    private function handleRateLimited(string $ip, int $now, HttpResponse $response): CheckOutcome
    {
        // The server answered, so the transport is healthy even though we are over quota.
        $this->resetCircuit();

        $until = $this->rateLimitReset($now, $response);
        $retryAfter = max(1, $until - $now);

        $this->cache->set(self::RATE_LIMIT_KEY, $until, $retryAfter);

        $evidence = ['ip' => $ip, 'rate_limited_until' => $until];
        $quota = $this->quotaHeaders($response);
        if ($quota !== []) {
            $evidence['quota'] = $quota;
        }

        $this->logger->warning('AbuseIPDB rate limit hit; backing off without an in-process retry', $evidence);

        return CheckOutcome::uncertain(
            $this->name(),
            \sprintf('AbuseIPDB rate limit hit; retry after %d second(s)', $retryAfter),
            $evidence,
        );
    }

    private function onTransportFailure(string $ip, int $now, string $reason): CheckOutcome
    {
        $this->recordFailure($now);

        return $this->failureOutcome($ip, $reason);
    }

    private function failureOutcome(string $ip, string $reason): CheckOutcome
    {
        $this->logger->error('AbuseIPDB lookup failed', ['ip' => $ip, 'reason' => $reason]);

        if ($this->config->bool('abuseipdb.fail_open', true)) {
            return CheckOutcome::uncertain($this->name(), 'AbuseIPDB lookup failed: ' . $reason, ['ip' => $ip]);
        }

        return CheckOutcome::error($this->name(), $reason);
    }

    private function recordFailure(int $now): void
    {
        $threshold = max(1, $this->config->int('abuseipdb.circuit_breaker.failures', 3));
        $cooldown = max(1, $this->config->int('abuseipdb.circuit_breaker.cooldown', 300));

        $failures = $this->circuitState()['failures'] + 1;
        $openUntil = $failures >= $threshold ? $now + $cooldown : 0;

        // Keep the counter for the cooldown window even before the breaker opens,
        // so "consecutive" survives across requests without a process-global state.
        $this->cache->set(self::CIRCUIT_KEY, ['failures' => $failures, 'open_until' => $openUntil], $cooldown);

        if ($openUntil > 0) {
            $this->logger->warning('AbuseIPDB circuit breaker opened', [
                'failures' => $failures,
                'open_until' => $openUntil,
            ]);
        }
    }

    private function resetCircuit(): void
    {
        $this->cache->delete(self::CIRCUIT_KEY);
    }

    /**
     * @return array{failures: int, open_until: int}
     */
    private function circuitState(): array
    {
        $cached = $this->cache->get(self::CIRCUIT_KEY);

        if (!\is_array($cached)) {
            return ['failures' => 0, 'open_until' => 0];
        }

        $failures = $cached['failures'] ?? 0;
        $openUntil = $cached['open_until'] ?? 0;

        return [
            'failures' => \is_int($failures) ? max(0, $failures) : 0,
            'open_until' => \is_int($openUntil) ? $openUntil : 0,
        ];
    }

    private function rateLimitedUntil(): int
    {
        $until = $this->cache->get(self::RATE_LIMIT_KEY);

        return \is_int($until) ? $until : 0;
    }

    /**
     * Absolute timestamp until which the API must not be called again.
     *
     * `Retry-After` may be a number of seconds or an HTTP date;
     * `X-RateLimit-Reset` is a Unix timestamp in the AbuseIPDB API, but some
     * proxies send "seconds from now", so both shapes are accepted.
     */
    private function rateLimitReset(int $now, HttpResponse $response): int
    {
        $retryAfter = trim($response->header('retry-after'));

        if ($retryAfter !== '') {
            if (ctype_digit($retryAfter)) {
                return $now + max(1, (int) $retryAfter);
            }

            $timestamp = strtotime($retryAfter);
            if ($timestamp !== false) {
                return max($now + 1, $timestamp);
            }
        }

        $reset = trim($response->header('x-ratelimit-reset'));
        if ($reset !== '' && ctype_digit($reset)) {
            $value = (int) $reset;

            return $value > 1_000_000_000 ? $value : $now + max(1, $value);
        }

        return $now + self::DEFAULT_RETRY_AFTER;
    }

    /**
     * @return array<string, string>
     */
    private function quotaHeaders(HttpResponse $response): array
    {
        $quota = [];

        foreach (['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'retry-after'] as $name) {
            $value = $response->header($name);
            if ($value !== '') {
                $quota[$name] = $value;
            }
        }

        return $quota;
    }

    private function decodePayload(string $body): mixed
    {
        try {
            return json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }

    private function cachedOutcome(mixed $cached): ?CheckOutcome
    {
        if (!\is_array($cached)) {
            return null;
        }

        $status = $cached['status'] ?? null;
        $score = $cached['score'] ?? null;
        $reason = $cached['reason'] ?? null;
        $evidence = $cached['evidence'] ?? [];

        if (!\is_string($status) || !\is_int($score) || !\is_string($reason)) {
            return null;
        }

        $statusEnum = CheckStatus::tryFrom($status);
        if ($statusEnum === null) {
            return null;
        }

        return new CheckOutcome($this->name(), $statusEnum, $score, $reason, $this->normalizeEvidence($evidence));
    }

    /**
     * @return array<string, mixed>
     */
    private function normalizeEvidence(mixed $evidence): array
    {
        if (!\is_array($evidence)) {
            return [];
        }

        $normalized = [];
        foreach ($evidence as $key => $value) {
            $normalized[(string) $key] = $value;
        }

        return $normalized;
    }
}
