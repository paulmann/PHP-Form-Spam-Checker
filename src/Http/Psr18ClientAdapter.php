<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

/**
 * PSR-18 transport adapter: lets an application reuse its existing HTTP client.
 *
 * This file references `Psr\...` types only in signatures; PHP loads it only
 * when the application actually constructs the adapter, so the runtime has no
 * hard dependency on `psr/http-client` / `psr/http-factory`.
 *
 * PSR-18 has no timeout concept: `HttpRequest::$timeout` is honoured by the
 * wrapped client's own configuration, not by this adapter.
 */
final readonly class Psr18ClientAdapter implements HttpClientInterface
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $factory,
        private ?StreamFactoryInterface $streamFactory = null,
    ) {}

    public function send(HttpRequest $request): HttpResponse
    {
        $psrRequest = $this->factory->createRequest($request->method, $request->url);

        foreach ($request->headers as $name => $value) {
            $psrRequest = $psrRequest->withHeader($name, $value);
        }

        if ($request->body !== '') {
            $psrRequest = $psrRequest->withBody($this->createBody($psrRequest, $request->body));
        }

        try {
            $psrResponse = $this->client->sendRequest($psrRequest);
        } catch (ClientExceptionInterface $exception) {
            throw new HttpClientException('PSR-18 request failed: ' . $exception->getMessage(), 0, $exception);
        }

        $headers = [];
        foreach ($psrResponse->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        return new HttpResponse($psrResponse->getStatusCode(), $headers, (string) $psrResponse->getBody());
    }

    private function createBody(RequestInterface $request, string $body): StreamInterface
    {
        if ($this->streamFactory !== null) {
            return $this->streamFactory->createStream($body);
        }

        // Without a stream factory the request body stream is written in place,
        // which every PSR-7 implementation shipped by a PSR-18 client supports.
        $stream = $request->getBody();
        $stream->write($body);

        return $stream;
    }
}
