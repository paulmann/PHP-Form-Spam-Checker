<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/**
 * Minimal PSR-7 request used by the adapter tests.
 */
final class FakeRequest extends FakeHttpMessage implements RequestInterface
{
    private ?string $requestTarget = null;

    private UriInterface $uri;

    /**
     * @param array<string, list<string>> $headers
     */
    public function __construct(
        private string $method = 'GET',
        string $uri = '',
        array $headers = [],
        ?StreamInterface $body = null,
    ) {
        parent::__construct();

        $this->uri = new FakeUri($uri);

        foreach ($headers as $name => $values) {
            $this->headers[$this->normalizeName($name)] = $values;
        }

        if ($body !== null) {
            $this->body = $body;
        }
    }

    public function getRequestTarget(): string
    {
        return $this->requestTarget ?? '/';
    }

    public function withRequestTarget(string $requestTarget): RequestInterface
    {
        $clone = clone $this;
        $clone->requestTarget = $requestTarget;

        return $clone;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function withMethod(string $method): RequestInterface
    {
        $clone = clone $this;
        $clone->method = $method;

        return $clone;
    }

    public function getUri(): UriInterface
    {
        return $this->uri;
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): RequestInterface
    {
        $clone = clone $this;
        $clone->uri = $uri;

        return $clone;
    }
}
