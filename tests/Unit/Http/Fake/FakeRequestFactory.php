<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;

/**
 * PSR-17 request factory that records every request it creates.
 */
final class FakeRequestFactory implements RequestFactoryInterface
{
    /**
     * @var list<RequestInterface>
     */
    public array $created = [];

    public function createRequest(string $method, $uri): RequestInterface
    {
        $request = new FakeRequest($method, \is_string($uri) ? $uri : '');
        $this->created[] = $request;

        return $request;
    }
}
