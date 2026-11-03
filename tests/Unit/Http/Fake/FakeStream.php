<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * Minimal in-memory PSR-7 stream for adapter tests.
 */
final class FakeStream implements StreamInterface
{
    public function __construct(private string $content = '') {}

    public function __toString(): string
    {
        return $this->content;
    }

    public function close(): void
    {
        $this->content = '';
    }

    public function detach(): mixed
    {
        $content = $this->content;
        $this->content = '';

        return $content;
    }

    public function getSize(): ?int
    {
        return \strlen($this->content);
    }

    public function tell(): int
    {
        return 0;
    }

    public function eof(): bool
    {
        return true;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new RuntimeException('FakeStream is not seekable.');
    }

    public function rewind(): void {}

    public function isWritable(): bool
    {
        return true;
    }

    public function write(string $string): int
    {
        $this->content .= $string;

        return \strlen($string);
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        return '';
    }

    public function getContents(): string
    {
        return $this->content;
    }

    public function getMetadata(?string $key = null): mixed
    {
        return null;
    }
}
