<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

/**
 * Immutable outbound HTTP request.
 */
final readonly class HttpRequest
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public string $method,
        public string $url,
        public array $headers = [],
        public string $body = '',
        public float $timeout = 2.0,
    ) {
    }
}
