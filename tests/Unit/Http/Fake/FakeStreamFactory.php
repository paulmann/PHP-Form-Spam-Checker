<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * PSR-17 stream factory that counts the streams it creates.
 */
final class FakeStreamFactory implements StreamFactoryInterface
{
    public int $created = 0;

    public function createStream(string $content = ''): StreamInterface
    {
        $this->created++;

        return new FakeStream($content);
    }

    public function createStreamFromFile(string $filename, string $mode = 'r'): StreamInterface
    {
        throw new RuntimeException('not used in tests');
    }

    public function createStreamFromResource($resource): StreamInterface
    {
        throw new RuntimeException('not used in tests');
    }
}
