<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network\Fake;

use FormSpamChecker\Http\HttpClientException;
use FormSpamChecker\Http\HttpClientInterface;
use FormSpamChecker\Http\HttpRequest;
use FormSpamChecker\Http\HttpResponse;
use Throwable;

/**
 * Scripted HTTP transport: every queued item is returned (or thrown) once,
 * in order, and every request is recorded for assertions.
 */
final class RecordingHttpClient implements HttpClientInterface
{
    /**
     * @var list<HttpRequest>
     */
    public array $requests = [];

    /**
     * @var list<HttpResponse|Throwable>
     */
    private array $queue = [];

    public function queue(HttpResponse|Throwable $item): void
    {
        $this->queue[] = $item;
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $this->requests[] = $request;

        $next = array_shift($this->queue);

        if ($next === null) {
            throw new HttpClientException('recording HTTP client queue is empty');
        }

        if ($next instanceof Throwable) {
            throw $next;
        }

        return $next;
    }

    public function callCount(): int
    {
        return \count($this->requests);
    }
}
