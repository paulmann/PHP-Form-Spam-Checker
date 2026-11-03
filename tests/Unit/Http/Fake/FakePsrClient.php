<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Scripted PSR-18 client: returns (or throws) queued items and records requests.
 */
final class FakePsrClient implements ClientInterface
{
    /**
     * @var list<RequestInterface>
     */
    public array $requests = [];

    /**
     * @var list<ResponseInterface|Throwable>
     */
    private array $queue = [];

    public function queue(ResponseInterface|Throwable $item): void
    {
        $this->queue[] = $item;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        $next = array_shift($this->queue);

        if ($next === null) {
            throw new FakeClientException('fake PSR-18 queue is empty');
        }

        if ($next instanceof Throwable) {
            throw $next;
        }

        return $next;
    }
}
