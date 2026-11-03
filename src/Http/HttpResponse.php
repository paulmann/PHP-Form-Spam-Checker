<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

/**
 * Immutable inbound HTTP response.
 */
final readonly class HttpResponse
{
    /**
     * @param array<string, string> $headers lower-case header names
     */
    public function __construct(
        public int $status,
        public array $headers = [],
        public string $body = '',
    ) {
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }
}
