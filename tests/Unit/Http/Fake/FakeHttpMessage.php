<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Shared PSR-7 message behaviour for the request/response fixtures.
 */
abstract class FakeHttpMessage implements MessageInterface
{
    /**
     * @var array<string, list<string>>
     */
    protected array $headers = [];

    protected string $protocol = '1.1';

    protected StreamInterface $body;

    public function __construct()
    {
        $this->body = new FakeStream();
    }

    public function getProtocolVersion(): string
    {
        return $this->protocol;
    }

    public function withProtocolVersion(string $version): MessageInterface
    {
        $clone = clone $this;
        $clone->protocol = $version;

        return $clone;
    }

    /**
     * @return array<string, list<string>>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return \array_key_exists($this->normalizeName($name), $this->headers);
    }

    /**
     * @return list<string>
     */
    public function getHeader(string $name): array
    {
        $key = $this->normalizeName($name);

        return $this->headers[$key] ?? [];
    }

    public function getHeaderLine(string $name): string
    {
        return implode(', ', $this->getHeader($name));
    }

    public function withHeader(string $name, $value): MessageInterface
    {
        $clone = clone $this;
        $clone->headers[$this->normalizeName($name)] = $this->headerValues($value);

        return $clone;
    }

    public function withAddedHeader(string $name, $value): MessageInterface
    {
        $clone = clone $this;
        $key = $this->normalizeName($name);
        $clone->headers[$key] = [...($clone->headers[$key] ?? []), ...$this->headerValues($value)];

        return $clone;
    }

    public function withoutHeader(string $name): MessageInterface
    {
        $clone = clone $this;
        unset($clone->headers[$this->normalizeName($name)]);

        return $clone;
    }

    public function getBody(): StreamInterface
    {
        return $this->body;
    }

    public function withBody(StreamInterface $body): MessageInterface
    {
        $clone = clone $this;
        $clone->body = $body;

        return $clone;
    }

    protected function normalizeName(string $name): string
    {
        return strtolower($name);
    }

    /**
     * @return list<string>
     */
    private function headerValues(mixed $value): array
    {
        if (!\is_array($value)) {
            return [\is_scalar($value) ? (string) $value : ''];
        }

        $values = [];
        foreach ($value as $item) {
            $values[] = \is_scalar($item) ? (string) $item : '';
        }

        return $values;
    }
}
