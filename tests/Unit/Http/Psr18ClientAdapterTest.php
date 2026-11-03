<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http;

use FormSpamChecker\Http\HttpClientException;
use FormSpamChecker\Http\HttpRequest;
use FormSpamChecker\Http\Psr18ClientAdapter;
use FormSpamChecker\Tests\Unit\Http\Fake\FakeClientException;
use FormSpamChecker\Tests\Unit\Http\Fake\FakePsrClient;
use FormSpamChecker\Tests\Unit\Http\Fake\FakeRequestFactory;
use FormSpamChecker\Tests\Unit\Http\Fake\FakeResponse;
use FormSpamChecker\Tests\Unit\Http\Fake\FakeStream;
use FormSpamChecker\Tests\Unit\Http\Fake\FakeStreamFactory;
use PHPUnit\Framework\TestCase;

final class Psr18ClientAdapterTest extends TestCase
{
    private FakePsrClient $client;

    private FakeRequestFactory $factory;

    protected function setUp(): void
    {
        $this->client = new FakePsrClient();
        $this->factory = new FakeRequestFactory();
    }

    public function testRequestIsConvertedToPsr7(): void
    {
        $this->client->queue(new FakeResponse(200, [], new FakeStream('ok')));

        $this->adapter()->send(new HttpRequest(
            method: 'POST',
            url: 'https://api.example.test/check',
            headers: ['Key' => 'secret', 'Accept' => 'application/json'],
            body: '{"q":1}',
            timeout: 1.5,
        ));

        $request = $this->client->requests[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://api.example.test/check', (string) $request->getUri());
        self::assertSame(['secret'], $request->getHeader('key'));
        self::assertSame(['application/json'], $request->getHeader('accept'));
        self::assertSame('{"q":1}', (string) $request->getBody());
    }

    public function testResponseIsConvertedToHttpResponse(): void
    {
        $this->client->queue(new FakeResponse(
            201,
            ['X-RateLimit-Limit' => ['10'], 'Content-Type' => ['application/json']],
            new FakeStream('{"data":{}}'),
        ));

        $response = $this->adapter()->send(new HttpRequest('GET', 'https://api.example.test/check'));

        self::assertSame(201, $response->status);
        self::assertSame('10', $response->header('x-ratelimit-limit'));
        self::assertSame('application/json', $response->header('content-type'));
        self::assertSame('{"data":{}}', $response->body);
    }

    public function testMultipleHeadersAreJoinedOnConversion(): void
    {
        $this->client->queue(new FakeResponse(200, ['Set-Cookie' => ['a=1', 'b=2']], new FakeStream('')));

        $response = $this->adapter()->send(new HttpRequest('GET', 'https://api.example.test/check'));

        self::assertSame('a=1, b=2', $response->header('set-cookie'));
    }

    public function testClientExceptionIsWrappedIntoHttpClientException(): void
    {
        $this->client->queue(new FakeClientException('connection refused'));

        $this->expectException(HttpClientException::class);
        $this->expectExceptionMessage('PSR-18 request failed: connection refused');

        $this->adapter()->send(new HttpRequest('GET', 'https://api.example.test/check'));
    }

    public function testEveryCallCreatesAFreshPsrRequest(): void
    {
        $this->client->queue(new FakeResponse(200, [], new FakeStream('')));
        $this->client->queue(new FakeResponse(404, [], new FakeStream('')));

        $adapter = $this->adapter();
        $adapter->send(new HttpRequest('GET', 'https://api.example.test/one'));
        $adapter->send(new HttpRequest('GET', 'https://api.example.test/two'));

        self::assertCount(2, $this->factory->created);
        self::assertSame('https://api.example.test/one', (string) $this->client->requests[0]->getUri());
        self::assertSame('https://api.example.test/two', (string) $this->client->requests[1]->getUri());
    }

    public function testBodyIsWrittenIntoTheRequestStreamWithoutAStreamFactory(): void
    {
        $this->client->queue(new FakeResponse(200, [], new FakeStream('')));

        $this->adapter()->send(new HttpRequest('POST', 'https://api.example.test/check', body: 'payload'));

        self::assertSame('payload', (string) $this->client->requests[0]->getBody());
    }

    public function testStreamFactoryIsUsedWhenProvided(): void
    {
        $streamFactory = new FakeStreamFactory();

        $this->client->queue(new FakeResponse(200, [], new FakeStream('')));

        $this->adapter($streamFactory)->send(new HttpRequest('POST', 'https://api.example.test/check', body: 'payload'));

        self::assertSame(1, $streamFactory->created);
        self::assertSame('payload', (string) $this->client->requests[0]->getBody());
    }

    public function testEmptyBodyDoesNotCreateAStream(): void
    {
        $streamFactory = new FakeStreamFactory();

        $this->client->queue(new FakeResponse(200, [], new FakeStream('')));

        $this->adapter($streamFactory)->send(new HttpRequest('GET', 'https://api.example.test/check'));

        self::assertSame(0, $streamFactory->created);
    }

    private function adapter(?FakeStreamFactory $streamFactory = null): Psr18ClientAdapter
    {
        return new Psr18ClientAdapter($this->client, $this->factory, $streamFactory);
    }
}
