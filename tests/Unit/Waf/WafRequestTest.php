<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf;

use FormSpamChecker\Waf\WafRequest;
use PHPUnit\Framework\TestCase;

final class WafRequestTest extends TestCase
{
    public function testFromGlobalsNormalisesHeadersAndExtractsTheRequest(): void
    {
        $request = WafRequest::fromGlobals(
            server: [
                'REQUEST_METHOD' => 'post',
                'REQUEST_URI' => '/api/lead?x=1',
                'REMOTE_ADDR' => '203.0.113.5',
                'HTTP_X_CUSTOM_HEADER' => 'abc',
                'HTTP_USER_AGENT' => 'Test UA',
                'CONTENT_TYPE' => 'application/json',
                'CONTENT_LENGTH' => '12',
            ],
            get: ['x' => '1', 'tags' => ['a']],
            post: ['name' => 'Иван'],
            cookie: ['sid' => 'abc'],
            body: '{"name":"x"',
        );

        self::assertSame('POST', $request->method);
        self::assertSame('/api/lead?x=1', $request->uri);
        self::assertSame('/api/lead', $request->path());
        self::assertSame('abc', $request->header('X-Custom-Header'));
        self::assertSame('Test UA', $request->userAgent());
        self::assertSame('1', $request->queryString('x'));
        self::assertSame('', $request->queryString('missing'));
        self::assertSame(['name' => 'Иван'], $request->fields);
        self::assertSame(['sid' => 'abc'], $request->cookies);
        self::assertSame('application/json', $request->contentType);
        self::assertSame(12, $request->contentLength);
        self::assertSame('203.0.113.5', $request->ip);
        self::assertFalse($request->isMultipart());
        self::assertSame('{"name":"x"', $request->scannableBody());
    }

    public function testQueryStringIsParsedWhenGetIsNotProvided(): void
    {
        $request = WafRequest::fromGlobals(
            server: ['REQUEST_URI' => '/search?a=1&b%5B%5D=2', 'QUERY_STRING' => 'a=1&b%5B%5D=2'],
            get: null,
            post: [],
            cookie: [],
        );

        self::assertSame('1', $request->queryString('a'));
        self::assertSame(['2'], $request->query['b']);
    }

    public function testBodyIsCappedAndContentLengthFallsBackToBodySize(): void
    {
        $request = WafRequest::fromGlobals(
            server: ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/'],
            get: [],
            post: [],
            cookie: [],
            body: str_repeat('a', 100),
            maxBodyBytes: 10,
        );

        self::assertSame(10, strlen($request->body));
        self::assertSame(10, $request->contentLength);
    }

    public function testForwardedForIsOnlyTrustedBehindALoopbackProxy(): void
    {
        $behindProxy = WafRequest::fromGlobals(
            server: [
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 10.0.0.1',
            ],
            get: [],
            post: [],
            cookie: [],
        );
        self::assertSame('198.51.100.7', $behindProxy->ip);

        $direct = WafRequest::fromGlobals(
            server: [
                'REMOTE_ADDR' => '203.0.113.9',
                'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
            ],
            get: [],
            post: [],
            cookie: [],
        );
        self::assertSame('203.0.113.9', $direct->ip);
    }

    public function testCloudflareAndRealIpHeadersWinOverTheRemoteAddress(): void
    {
        $request = WafRequest::fromGlobals(
            server: [
                'REMOTE_ADDR' => '10.0.0.1',
                'HTTP_CF_CONNECTING_IP' => '198.51.100.20',
                'HTTP_X_REAL_IP' => '198.51.100.30',
            ],
            get: [],
            post: [],
            cookie: [],
        );

        self::assertSame('198.51.100.20', $request->ip);
    }

    public function testMultipartBodiesAreNotScannable(): void
    {
        $request = WafRequest::fromGlobals(
            server: [
                'REQUEST_METHOD' => 'POST',
                'REQUEST_URI' => '/upload',
                'CONTENT_TYPE' => 'multipart/form-data; boundary=xyz',
            ],
            get: [],
            post: [],
            cookie: [],
            body: "binary\x00data",
        );

        self::assertTrue($request->isMultipart());
        self::assertTrue($request->bodyIsBinary());
        self::assertSame('', $request->scannableBody());
    }

    public function testBinaryBodyIsDetectedByNulAndInvalidUtf8(): void
    {
        $nul = new WafRequest(body: "\x00bad", contentType: 'application/octet-stream');
        self::assertTrue($nul->bodyIsBinary());
        self::assertSame('', $nul->scannableBody());

        $invalid = new WafRequest(body: "\xFF\xFE", contentType: 'application/octet-stream');
        self::assertTrue($invalid->bodyIsBinary());
        self::assertSame('', $invalid->scannableBody());
    }

    public function testHeaderLookupIsCaseInsensitiveForManualRequests(): void
    {
        $request = new WafRequest(headers: ['X-Test' => 'value']);

        self::assertSame('value', $request->header('x-test'));
        self::assertSame('value', $request->header('X-TEST'));
        self::assertTrue($request->hasHeader('x-test'));
        self::assertFalse($request->hasHeader('missing'));
    }

    public function testPathHandlesQueryStringAndEmptyUri(): void
    {
        self::assertSame('/a/b', (new WafRequest(uri: '/a/b?c=1'))->path());
        self::assertSame('/', (new WafRequest(uri: '?'))->path());
        self::assertSame('/', (new WafRequest(uri: ''))->path());
    }

    public function testEffectiveContentTypeFallsBackToTheHeader(): void
    {
        $request = new WafRequest(headers: ['content-type' => 'application/json']);

        self::assertSame('application/json', $request->effectiveContentType());
    }

    public function testFakeClockIsUsedForTheTimestamp(): void
    {
        self::assertSame(1_700_000_000, (new WafRequest(now: 1_700_000_000))->timestamp());
        self::assertGreaterThan(0, (new WafRequest())->timestamp());
    }
}
