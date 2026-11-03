<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Minimal PSR-7 response used by the adapter tests.
 */
final class FakeResponse extends FakeHttpMessage implements ResponseInterface
{
    /**
     * @param array<string, list<string>> $headers
     */
    public function __construct(
        private int $status = 200,
        array $headers = [],
        ?StreamInterface $body = null,
        private string $reasonPhrase = '',
    ) {
        parent::__construct();

        foreach ($headers as $name => $values) {
            $this->headers[$this->normalizeName($name)] = $values;
        }

        if ($body !== null) {
            $this->body = $body;
        }
    }

    public function getStatusCode(): int
    {
        return $this->status;
    }

    public function withStatus(int $code, string $reasonPhrase = ''): ResponseInterface
    {
        $clone = clone $this;
        $clone->status = $code;
        $clone->reasonPhrase = $reasonPhrase;

        return $clone;
    }

    public function getReasonPhrase(): string
    {
        return $this->reasonPhrase;
    }
}
