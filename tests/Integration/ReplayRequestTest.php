<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Integration\RejectedStore;
use FormSpamChecker\Integration\ReplayRequest;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use InvalidArgumentException;

/**
 * Rebuilding a replayable request from a rejected-form record, including the
 * safety rules (dry run by default, no secrets, same host, stored uploads).
 */
final class ReplayRequestTest extends TempDirTestCase
{
    /**
     * @param  array<string, mixed>               $overrides
     * @return array{0: Config, 1: RejectedStore}
     */
    private function boot(string $root, array $overrides = []): array
    {
        $config = new Config(array_replace_recursive([
            'storage' => ['driver' => 'file', 'path' => $root . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . 'example.ru'],
            'log' => ['enabled' => false],
        ], $overrides));

        return [$config, new RejectedStore($config, 'example.ru')];
    }

    /**
     * @param  array<string, mixed> $fields
     * @param  array<string, mixed> $files
     * @return array<string, mixed>
     */
    private function capture(Config $config, array $fields = [], array $files = []): array
    {
        if ($fields === []) {
            $fields = ['name' => 'John Smith', 'email' => 'john@example.com', 'tags' => ['a', 'b']];
        }

        $request = new RequestData(
            fields: $fields,
            ip: '203.0.113.77',
            headers: [
                'host' => 'example.ru',
                'user-agent' => 'Mozilla/5.0 replay-test',
                'referer' => 'https://example.ru/contact/',
                'origin' => 'https://example.ru',
                'accept-language' => 'ru-RU,ru;q=0.9',
                'content-type' => 'application/x-www-form-urlencoded',
                'cookie' => 'sid=secret-session',
                'authorization' => 'Bearer top-secret',
            ],
            method: 'POST',
            uri: '/contact/?utm=letter',
            formId: 'lead',
        );

        $verdict = new Verdict(Status::Spam, 60, [
            CheckOutcome::suspicious('language', 60, '1 name field(s) contain no Cyrillic letters'),
        ]);

        $record = RejectedStore::capture(
            $request,
            $config,
            $verdict,
            'example.ru',
            'lead',
            RejectedStore::REASON_SPAM,
            ['HTTPS' => 'on', 'HTTP_HOST' => 'example.ru'],
            $files,
        );

        self::assertIsArray($record);

        return $record;
    }

    public function testBuildsTheOriginalUrlencodedRequestAndDropsSecrets(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['store_headers_secrets' => true]]);
        $record = $this->capture($config);

        // Secrets were kept for inspection but must never be replayed.
        self::assertArrayHasKey('cookie', $record['request']['headers']);

        $replay = ReplayRequest::fromRecord($record, null, $store->directory());

        self::assertSame('POST', $replay->method);
        self::assertSame('https://example.ru/contact/?utm=letter', $replay->url);
        self::assertSame('application/x-www-form-urlencoded', $replay->contentType);
        self::assertStringContainsString('name=John+Smith', $replay->body);
        self::assertStringContainsString('email=john%40example.com', $replay->body);
        self::assertStringContainsString('tags%5B0%5D=a', $replay->body);
        self::assertSame('Mozilla/5.0 replay-test', $replay->headers['User-Agent'] ?? null);
        self::assertSame('ru-RU,ru;q=0.9', $replay->headers['Accept-Language'] ?? null);
        self::assertArrayNotHasKey('Cookie', $replay->headers);
        self::assertArrayNotHasKey('Authorization', $replay->headers);
        self::assertArrayNotHasKey('Host', $replay->headers);
    }

    public function testDryRunByDefaultNeverSends(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);
        $record = $this->capture($config);
        $replay = ReplayRequest::fromRecord($record, null, $store->directory());

        $plan = $replay->replay();

        self::assertFalse($plan['sent']);
        self::assertFalse($plan['confirmed']);
        self::assertSame('POST', $plan['method']);
        self::assertSame('https://example.ru/contact/?utm=letter', $plan['url']);
        self::assertGreaterThan(0, $plan['body_bytes']);
        self::assertArrayNotHasKey('status', $plan);
    }

    public function testRefusesWhenUploadsWereNotStored(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        [$config, $store] = $this->boot($root);
        $record = $this->capture($config, files: [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('uploaded files');

        ReplayRequest::fromRecord($record, null, $store->directory());
    }

    public function testStoredUploadsAreReplayedAsMultipart(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        [$config, $store] = $this->boot($root, ['rejected' => ['store_files' => true]]);
        $record = $this->capture($config, files: [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ]);

        $replay = ReplayRequest::fromRecord($record, null, $store->directory());

        self::assertStringStartsWith('multipart/form-data; boundary=', $replay->contentType);
        self::assertStringContainsString('filename="quote.pdf"', $replay->body);
        self::assertStringContainsString('PDFDATA', $replay->body);
        self::assertStringContainsString('name="name"', $replay->body);
        self::assertCount(1, $replay->files);
    }

    public function testTargetValidationRefusesAnotherHostUnlessAllowed(): void
    {
        $root = $this->tempDir();
        [$config] = $this->boot($root);
        $record = $this->capture($config);

        self::assertNull(ReplayRequest::checkTarget($record, null, false));
        self::assertNull(ReplayRequest::checkTarget($record, 'https://example.ru/other', false));

        $refusal = ReplayRequest::checkTarget($record, 'https://evil.example/contact/', false);
        self::assertIsString($refusal);
        self::assertStringContainsString('--allow-host-change', $refusal);

        self::assertNull(ReplayRequest::checkTarget($record, 'https://evil.example/contact/', true));
    }

    public function testRejectsNonHttpTargetsAndNonReplayableMethods(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);
        $record = $this->capture($config);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('http');

        ReplayRequest::fromRecord($record, 'file:///etc/passwd', $store->directory());
    }

    public function testSendParsesAResponseAndReportsTransportFailure(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);
        $record = $this->capture($config);
        $replay = ReplayRequest::fromRecord($record, null, $store->directory());

        $ok = $replay->send(
            1.0,
            static fn(): array => ['{"ok":true}', ['HTTP/1.1 200 OK', 'Content-Type: application/json']],
        );
        self::assertTrue($ok['sent']);
        self::assertTrue($ok['ok']);
        self::assertSame(200, $ok['status']);
        self::assertSame('{"ok":true}', $ok['body']);
        self::assertSame('', $ok['error']);

        $redirect = $replay->send(1.0, static fn(): array => ['', ['HTTP/1.1 302 Found']]);
        self::assertTrue($redirect['ok']);
        self::assertSame(302, $redirect['status']);

        $failed = $replay->send(1.0, static fn(): array => [false, []]);
        self::assertSame(0, $failed['status']);
        self::assertFalse($failed['ok']);
        self::assertNotSame('', $failed['error']);
    }

    public function testRefusesNonPostWafBlocks(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $request = new \FormSpamChecker\Waf\WafRequest(
            method: 'GET',
            uri: '/.env',
            ip: '203.0.113.77',
            body: '',
            contentType: '',
            contentLength: 0,
            headers: ['host' => 'example.ru', 'user-agent' => 'scanner'],
        );

        $record = RejectedStore::capture(
            $request,
            $config,
            new \FormSpamChecker\Waf\WafVerdict(true, 100, [], \FormSpamChecker\Waf\WafVerdict::STATUS_BLOCKED),
            'example.ru',
            'default',
            RejectedStore::REASON_WAF,
        );

        self::assertIsArray($record);
        self::assertSame('GET', $record['request']['method']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('POST, PUT and PATCH');

        ReplayRequest::fromRecord($record, null, $store->directory());
    }

    public function testOriginalUrlFallsBackToStoredRequestParts(): void
    {
        self::assertSame(
            'https://example.ru/lead',
            ReplayRequest::originalUrl(['request' => ['host' => 'example.ru', 'uri' => '/lead', 'scheme' => 'https']]),
        );
        self::assertSame('', ReplayRequest::originalUrl(['request' => []]));
        self::assertSame('', ReplayRequest::hostOf('not a url'));
        self::assertSame('example.ru', ReplayRequest::hostOf('https://EXAMPLE.ru./x'));
    }

    public function testFromRecordRejectsARecordWithoutUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('no request URL');

        ReplayRequest::fromRecord(['request' => []]);
    }

    public function testFromRecordRejectsAnUnstoredPayload(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not stored');

        ReplayRequest::fromRecord([
            'request' => ['url' => 'https://example.ru/lead', 'method' => 'POST'],
            'payload' => ['stored' => false],
        ]);
    }

    public function testTruncatedRecordIsReplayedWithAWarningAndToArrayIsComplete(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['max_bytes_per_record' => 4096]]);
        $record = $this->capture($config, ['message' => str_repeat('x', 8000)]);

        self::assertTrue($record['truncated']);

        $replay = ReplayRequest::fromRecord($record, null, $store->directory());
        $array = $replay->toArray();

        self::assertSame('POST', $array['method']);
        self::assertSame('https://example.ru/contact/?utm=letter', $array['url']);
        self::assertGreaterThan(0, $array['body_bytes']);
        self::assertNotSame([], $array['warnings']);
        self::assertStringContainsString('truncated', (string) $array['warnings'][0]);
    }

    public function testStoredUploadsNeedTheRegistryDirectory(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        [$config] = $this->boot($root, ['rejected' => ['store_files' => true]]);
        $record = $this->capture($config, files: [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('registry directory');

        ReplayRequest::fromRecord($record, null, null);
    }

    public function testMissingStoredUploadIsRefused(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        [$config, $store] = $this->boot($root, ['rejected' => ['store_files' => true]]);
        $record = $this->capture($config, files: [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ]);

        $storedPath = $store->directory() . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, (string) $record['payload']['files'][0]['stored_path']);
        self::assertFileExists($storedPath);
        unlink($storedPath);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('missing or outside');

        ReplayRequest::fromRecord($record, null, $store->directory());
    }

    public function testCheckTargetEdgeCases(): void
    {
        self::assertSame(
            'The record has no request URL; pass --url=',
            ReplayRequest::checkTarget(['request' => []], null, false),
        );

        $refusal = ReplayRequest::checkTarget(['request' => ['url' => 'https://example.ru/x']], 'not-a-url', false);
        self::assertIsString($refusal);
        self::assertStringContainsString('no host', $refusal);

        self::assertNull(ReplayRequest::checkTarget(
            ['request' => ['url' => 'https://example.ru/x']],
            'https://example.ru/y',
            false,
        ));
    }
}
