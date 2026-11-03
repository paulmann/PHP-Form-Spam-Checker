<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Transport-level sanity of an HTTP request.
 *
 * Checks, in order: the method allowlist, the declared body size, the
 * Content-Type of requests that carry a body, and the Host header. A
 * disallowed method or an oversized body is hard; a surprising Content-Type or
 * a syntactically odd Host is score-only by default, because custom clients do
 * send unusual but harmless values. Both are configurable.
 */
final class ProtocolRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 70;

    protected const bool DEFAULT_HARD = true;

    /** @var list<string> */
    private const array METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

    /** @var list<string> */
    private const array CONTENT_TYPES = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'application/json',
        'application/*+json',
        'text/plain',
    ];

    /** @var list<string> */
    private const array BODY_METHODS = ['POST', 'PUT', 'PATCH'];

    private const string HOST_PATTERN = '/^(?:[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?|\[[0-9a-f:.]{2,45}\])'
        . '(?::\d{1,5})?$/i';

    public function name(): string
    {
        return 'protocol';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $method = strtoupper($request->method);
        $methods = array_map(
            static fn(string $allowed): string => strtoupper($allowed),
            $this->listOption('methods', self::METHODS),
        );

        if ($method === '' || !\in_array($method, $methods, true)) {
            return $this->finding(
                'request method is not allowed',
                'method',
                ['method' => $request->method],
                null,
                true,
            );
        }

        $maxBodyBytes = max(0, $this->intOption(
            'max_body_bytes',
            $this->config->int('waf.max_body_bytes', WafRequest::DEFAULT_MAX_BODY_BYTES),
        ));

        $contentLength = $request->declaredContentLength();

        if ($contentLength < 0) {
            return $this->finding(
                'negative Content-Length',
                'header.content-length',
                ['content_length' => $contentLength],
                null,
                true,
            );
        }

        if ($contentLength > $maxBodyBytes || \strlen($request->body) > $maxBodyBytes) {
            return $this->finding(
                'request body exceeds the configured limit',
                'body',
                [
                    'content_length' => $contentLength,
                    'body_bytes' => \strlen($request->body),
                    'max_body_bytes' => $maxBodyBytes,
                ],
                null,
                true,
            );
        }

        if (\in_array($method, self::BODY_METHODS, true)) {
            $contentType = strtolower(trim(explode(';', $request->effectiveContentType(), 2)[0]));
            $allowed = $this->listOption('content_types', self::CONTENT_TYPES);

            if (!$this->contentTypeAllowed($contentType, $allowed)) {
                return $this->finding(
                    'Content-Type is not allowed for a request with a body',
                    'header.content-type',
                    ['content_type' => mb_substr($contentType, 0, 120)],
                    max(0, min(100, $this->intOption('content_type_severity', 40))),
                    $this->boolOption('content_type_hard', false),
                );
            }
        }

        return $this->checkHost($request);
    }

    private function checkHost(WafRequest $request): ?WafFinding
    {
        $host = trim($request->header('host'));

        if ($host === '') {
            return $this->finding(
                'missing Host header',
                'header.host',
                [],
                max(0, min(100, $this->intOption('host_severity', 25))),
                false,
            );
        }

        if (preg_match(self::HOST_PATTERN, $host) === 1) {
            return null;
        }

        return $this->finding(
            'Host header is not a valid host name',
            'header.host',
            ['host' => mb_substr($host, 0, 120)],
            max(0, min(100, $this->intOption('host_severity', 50))),
            $this->boolOption('host_hard', false),
        );
    }

    /**
     * @param list<string> $allowed
     */
    private function contentTypeAllowed(string $contentType, array $allowed): bool
    {
        if ($contentType === '') {
            return false;
        }

        foreach ($allowed as $entry) {
            $entry = strtolower(trim($entry));

            if ($entry === '') {
                continue;
            }

            $pattern = '/^' . str_replace('\*', '.*', preg_quote($entry, '/')) . '$/';

            if (preg_match($pattern, $contentType) === 1) {
                return true;
            }
        }

        return false;
    }

    private function intOption(string $key, int $default): int
    {
        $value = $this->option($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }

    private function boolOption(string $key, bool $default): bool
    {
        $value = $this->option($key, $default);

        if (\is_bool($value)) {
            return $value;
        }

        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? $default;
    }
}
