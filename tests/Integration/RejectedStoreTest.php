<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Integration\RejectedStore;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use stdClass;

/**
 * The registry of rejected (unsent) form submissions: capture, hard limits,
 * lifecycle, retention, uploads and the fail-open guard wiring.
 */
final class RejectedStoreTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    /**
     * @param  array<string, mixed>               $overrides
     * @return array{0: Config, 1: RejectedStore}
     */
    private function boot(string $root, array $overrides = []): array
    {
        $values = [
            'storage' => ['driver' => 'file', 'path' => $root . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . 'example.ru'],
            'log' => ['enabled' => false],
        ];

        $config = new Config(array_replace_recursive($values, $overrides));
        $store = new RejectedStore($config, 'example.ru');

        return [$config, $store];
    }

    private function spamVerdict(): Verdict
    {
        return new Verdict(Status::Spam, 60, [
            CheckOutcome::suspicious('language', 60, '1 name field(s) contain no Cyrillic letters'),
        ]);
    }

    /**
     * @param array<string, mixed> $fields
     */
    private function request(array $fields = [], string $formId = 'lead', string $body = ''): RequestData
    {
        if ($fields === []) {
            $fields = [
                'name' => 'John Smith',
                'email' => 'john@example.com',
                'phone' => '+7 999 123-45-67',
                'message' => 'Need a quote for a battery',
                'tags' => ['a', 'b'],
            ];
        }

        return new RequestData(
            fields: $fields,
            ip: '203.0.113.77',
            headers: [
                'host' => 'example.ru',
                'user-agent' => self::UA,
                'referer' => 'https://example.ru/contact/',
                'origin' => 'https://example.ru',
                'content-type' => 'application/x-www-form-urlencoded',
                'cookie' => 'sid=secret-session',
            ],
            query: ['utm' => 'letter'],
            method: 'POST',
            uri: '/contact/?utm=letter',
            body: $body,
            formId: $formId,
        );
    }

    /**
     * @param  array<string, mixed>      $files
     * @return array<string, mixed>|null
     */
    private function capture(
        Config $config,
        string $site = 'example.ru',
        string $form = 'lead',
        ?Verdict $verdict = null,
        array $files = [],
        string $body = '',
        string $reason = RejectedStore::REASON_SPAM,
    ): ?array {
        return RejectedStore::capture(
            $this->request(body: $body),
            $config,
            $verdict ?? $this->spamVerdict(),
            $site,
            $form,
            $reason,
            ['HTTPS' => 'on', 'HTTP_HOST' => $site, 'REQUEST_URI' => '/contact/?utm=letter'],
            $files,
        );
    }

    public function testCaptureWritesFullRecordWithPayloadAndReason(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $record = $this->capture($config);

        self::assertIsArray($record);
        self::assertSame('new', $record['status']);
        self::assertSame('example.ru', $record['site']);
        self::assertSame('lead', $record['form']);
        self::assertSame('form', $record['source']);
        self::assertSame('spam', $record['reason']);
        self::assertTrue($record['would_reject']);
        self::assertSame(self::UA, $record['client']['user_agent']);
        self::assertSame('203.0.113.77', $record['client']['ip']);
        self::assertSame('https://example.ru/contact/?utm=letter', $record['request']['url']);
        self::assertSame('POST', $record['request']['method']);
        self::assertSame(['utm' => 'letter'], $record['request']['query']);

        // Raw payload: values are not trimmed, arrays are preserved.
        self::assertSame('John Smith', $record['payload']['fields']['name']);
        self::assertSame('john@example.com', $record['payload']['fields']['email']);
        self::assertSame(['a', 'b'], $record['payload']['fields']['tags']);

        // Cookies are secrets: never stored unless explicitly requested.
        self::assertArrayNotHasKey('cookie', $record['request']['headers']);

        self::assertSame(
            'language: 1 name field(s) contain no Cyrillic letters',
            RejectedStore::firstReason($record),
        );
        self::assertSame('https', $record['request']['scheme']);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/', $record['ts']);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $record['ts_utc']);
        self::assertSame('spam', $record['verdict']['status']);
        self::assertSame(60, $record['verdict']['score']);
        self::assertSame('form', $record['verdict']['kind']);

        $file = $store->directory() . DIRECTORY_SEPARATOR . $record['id'] . '.json';

        self::assertFileExists($file);
        self::assertDirectoryExists(\dirname($store->directory()));
        self::assertFileExists(\dirname($store->directory()) . DIRECTORY_SEPARATOR . '.htaccess');
        self::assertSame($record['id'], $store->find($record['id'])['id'] ?? null);

        $listed = $store->listRecords();
        self::assertCount(1, $listed);
        self::assertSame($record['id'], $listed[0]['id']);
    }

    public function testCleanVerdictAndDisabledRegistryWriteNothing(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        self::assertNull(RejectedStore::capture(
            $this->request(),
            $config,
            Verdict::clean(),
            'example.ru',
            'lead',
        ));

        self::assertSame([], $store->listRecords());
        self::assertDirectoryDoesNotExist(\dirname($store->directory()) . DIRECTORY_SEPARATOR . 'example.ru');

        [$disabled] = $this->boot($root, ['rejected' => ['enabled' => false]]);

        self::assertNull($this->capture($disabled));
        self::assertSame([], $store->listRecords());
    }

    public function testSuspiciousIsCapturedOnlyWhenConfiguredAsDecoy(): void
    {
        $root = $this->tempDir();
        [$config] = $this->boot($root);
        $suspicious = new Verdict(Status::Suspicious, 40, [
            CheckOutcome::suspicious('keywords', 40, 'casino'),
        ]);

        // Default: a suspicious verdict never writes (it never blocked either).
        self::assertNull($this->capture($config, verdict: $suspicious, reason: RejectedStore::REASON_SUSPICIOUS));

        [$enabled, $store] = $this->boot($root, ['rejected' => ['capture_suspicious' => true]]);
        $record = $this->capture($enabled, verdict: $suspicious, reason: RejectedStore::REASON_SUSPICIOUS);

        self::assertIsArray($record);
        self::assertFalse($record['would_reject']);
        self::assertSame('suspicious', $record['reason']);
        self::assertSame('suspicious', $record['verdict']['status']);
        self::assertCount(1, $store->listRecords());
    }

    public function testOversizedRecordIsTruncatedWithMarkerAndStaysValidJson(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['max_bytes_per_record' => 1024]]);

        $record = $this->capture(
            $config,
            body: str_repeat('y', 6000),
        );

        self::assertIsArray($record);
        self::assertTrue($record['truncated']);
        self::assertNotSame([], $record['truncated_fields']);

        $file = $store->directory() . DIRECTORY_SEPARATOR . $record['id'] . '.json';
        self::assertFileExists($file);
        self::assertLessThanOrEqual(1024, (int) filesize($file));

        $raw = (string) file_get_contents($file);
        self::assertStringContainsString('[truncated]', $raw);

        $decoded = json_decode($raw, true);
        self::assertIsArray($decoded);
        self::assertSame($record['id'], $decoded['id']);
        self::assertTrue($decoded['truncated']);
    }

    public function testMaxRecordsPerSitePrunesOldest(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['max_records_per_site' => 3]]);

        $ids = [];

        for ($i = 0; $i < 5; $i++) {
            $record = $this->capture($config);
            self::assertIsArray($record);
            $ids[] = $record['id'];
            usleep(2_000);
        }

        $files = glob($store->directory() . DIRECTORY_SEPARATOR . '*.json');
        self::assertIsArray($files);
        self::assertCount(3, $files);

        self::assertFileDoesNotExist($store->directory() . DIRECTORY_SEPARATOR . $ids[0] . '.json');
        self::assertFileDoesNotExist($store->directory() . DIRECTORY_SEPARATOR . $ids[1] . '.json');
        self::assertFileExists($store->directory() . DIRECTORY_SEPARATOR . $ids[4] . '.json');
    }

    public function testPurgeRemovesOnlyExpiredRecords(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $old = $this->capture($config);
        $new = $this->capture($config);
        self::assertIsArray($old);
        self::assertIsArray($new);

        // Age the file: purge works on the filesystem mtime.
        $oldFile = $store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json';
        touch($oldFile, time() - 40 * 86400);

        self::assertSame([$old['id']], $store->purgeCandidates(30));
        self::assertSame([$old['id']], $store->purge(30));

        self::assertFileDoesNotExist($oldFile);
        self::assertFileExists($store->directory() . DIRECTORY_SEPARATOR . $new['id'] . '.json');
        self::assertSame([], $store->purgeCandidates(30));
    }

    public function testStatusLifecycleIgnoreExpiredList(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $record = $this->capture($config);
        self::assertIsArray($record);

        self::assertTrue($store->ignore($record['id'], 'duplicate of ticket 42'));
        $loaded = $store->find($record['id']);
        self::assertIsArray($loaded);
        self::assertSame('ignored', $loaded['status']);
        self::assertSame('duplicate of ticket 42', $loaded['ignore_reason']);
        self::assertSame('ignored', $store->effectiveStatus($loaded));

        $expired = $loaded;
        $expired['status'] = 'new';
        $expired['ts_epoch'] = time() - 40 * 86400;
        self::assertSame('expired', $store->effectiveStatus($expired));

        self::assertCount(1, $store->listRecords(['status' => 'ignored']));
        self::assertSame([], $store->listRecords(['status' => 'new']));
        self::assertSame('lead', $loaded['form']);
        self::assertCount(1, $store->listRecords(['form' => 'lead']));
        self::assertSame([], $store->listRecords(['form' => 'other']));
        self::assertCount(1, $store->listRecords(['since' => (int) $loaded['ts_epoch'] - 5]));
        self::assertSame([], $store->listRecords(['limit' => 0]));
    }

    public function testUploadsAreStoredAsMetadataAndCopyWhenEnabled(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        $files = [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ];

        [$config] = $this->boot($root);
        $record = $this->capture($config, files: $files);
        self::assertIsArray($record);
        self::assertCount(1, $record['payload']['files']);
        self::assertSame('quote.pdf', $record['payload']['files'][0]['name']);
        self::assertSame(7, $record['payload']['files'][0]['size']);
        self::assertSame(hash('sha256', 'PDFDATA'), $record['payload']['files'][0]['sha256']);
        self::assertFalse($record['payload']['files'][0]['stored']);

        [$storing, $store] = $this->boot($root, ['rejected' => ['store_files' => true]]);
        $stored = $this->capture($storing, files: $files);
        self::assertIsArray($stored);
        self::assertTrue($stored['payload']['files'][0]['stored']);
        self::assertIsString($stored['payload']['files'][0]['stored_path']);
        self::assertFileExists(
            $store->directory() . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, (string) $stored['payload']['files'][0]['stored_path']),
        );

        $masked = RejectedStore::maskRecord($stored);
        self::assertStringContainsString('[hidden', (string) $masked['payload']['files'][0]['name']);
        self::assertArrayNotHasKey('stored_path', $masked['payload']['files'][0]);
    }

    public function testMaskedRecordHidesPersonalData(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $record = $this->capture($config);
        self::assertIsArray($record);

        $masked = RejectedStore::maskRecord($record);

        self::assertSame('[hidden 10 chars]', $masked['payload']['fields']['name']);
        self::assertSame('[hidden 16 chars]', $masked['payload']['fields']['email']);
        self::assertSame('203.0.***.***', $masked['client']['ip']);
        self::assertStringContainsString('[hidden', (string) $masked['request']['url']);
        self::assertTrue($masked['personal_data']['has_email']);
        self::assertTrue($masked['personal_data']['has_phone']);

        $summary = $store->summarize($record);
        self::assertSame('lead', $summary['form']);
        self::assertSame(60, $summary['score']);
        self::assertTrue($summary['has_email']);
        self::assertTrue($summary['has_phone']);
        self::assertStringNotContainsString('john@example.com', json_encode($summary, JSON_THROW_ON_ERROR));
    }

    public function testSecretHeadersStoredOnlyOnExplicitConfiguration(): void
    {
        $root = $this->tempDir();
        [$storing] = $this->boot($root, ['rejected' => ['store_headers_secrets' => true]]);

        $record = $this->capture($storing);

        self::assertIsArray($record);
        self::assertSame('sid=secret-session', $record['request']['headers']['cookie']);
    }

    public function testFormGuardCapturesBeforeBlockingAndCleanRequestWritesNothing(): void
    {
        $root = $this->tempDir();
        $configDir = $root . DIRECTORY_SEPARATOR . 'sites';
        mkdir($configDir, 0775, true);

        $siteConfig = [
            'site' => 'guard.example',
            'mode' => 'enforce',
            'form' => 'lead',
            'match' => ['#^/contact#'],
            'skip' => [],
            'response' => 'json',
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
                'rejected' => ['path' => $root . DIRECTORY_SEPARATOR . 'registry'],
            ],
        ];

        file_put_contents(
            $configDir . DIRECTORY_SEPARATOR . 'guard.php',
            '<?php return ' . var_export($siteConfig, true) . ';',
        );

        $spam = $this->runGuardSubprocess($configDir, ['name' => 'bot', 'website' => 'filled']);
        self::assertStringContainsString('spam_detected', $spam['stdout'], $spam['stderr'] . ' / ' . $spam['code']);

        $files = glob($root . DIRECTORY_SEPARATOR . 'registry' . DIRECTORY_SEPARATOR . '*.json');
        self::assertIsArray($files);
        self::assertCount(1, $files);

        $record = json_decode((string) file_get_contents($files[0]), true);
        self::assertIsArray($record);
        self::assertSame('spam', $record['reason']);
        self::assertTrue($record['would_reject']);
        self::assertSame('filled', $record['payload']['fields']['website']);
        self::assertSame('203.0.113.92', $record['client']['ip']);

        $clean = $this->runGuardSubprocess($configDir, [
            'name' => 'Иван Петров',
            'email' => 'ivan@example.com',
            'message' => 'Нужен отчёт за октябрь.',
        ]);
        self::assertStringContainsString('PASSED', $clean['stdout']);

        $files = glob($root . DIRECTORY_SEPARATOR . 'registry' . DIRECTORY_SEPARATOR . '*.json');
        self::assertIsArray($files);
        self::assertCount(1, $files);
    }

    public function testWafGuardCapturesBlockedRequests(): void
    {
        $root = $this->tempDir();
        $configDir = $root . DIRECTORY_SEPARATOR . 'sites';
        mkdir($configDir, 0775, true);

        $siteConfig = [
            'site' => 'waf.example',
            'waf_mode' => 'block',
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
                'waf' => ['enabled' => true, 'mode' => 'block'],
                'rejected' => ['path' => $root . DIRECTORY_SEPARATOR . 'registry-waf'],
            ],
        ];

        file_put_contents(
            $configDir . DIRECTORY_SEPARATOR . 'waf.php',
            '<?php return ' . var_export($siteConfig, true) . ';',
        );

        $result = $this->runWafGuardSubprocess($configDir);
        self::assertStringNotContainsString('PASSED', $result['stdout']);

        $files = glob($root . DIRECTORY_SEPARATOR . 'registry-waf' . DIRECTORY_SEPARATOR . '*.json');
        self::assertIsArray($files);
        self::assertCount(1, $files);

        $record = json_decode((string) file_get_contents($files[0]), true);
        self::assertIsArray($record);
        self::assertSame('waf', $record['source']);
        self::assertSame('waf', $record['reason']);
        self::assertSame('waf', $record['verdict']['kind']);
        self::assertTrue($record['would_reject']);
        self::assertNotSame([], RejectedStore::reasons($record));
    }

    public function testCorruptAndUnsafeRecordsAreSkipped(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);
        $record = $this->capture($config);
        self::assertIsArray($record);

        $directory = $store->directory();
        file_put_contents($directory . DIRECTORY_SEPARATOR . 'corrupt.json', '{not json');
        file_put_contents($directory . DIRECTORY_SEPARATOR . 'not-a-record.json', '{"foo":"bar"}');

        self::assertSame([$record['id']], array_column($store->listRecords(), 'id'));
        self::assertNull($store->find('../outside'));
        self::assertNull($store->find(''));
        self::assertNull($store->find('corrupt'));
        self::assertFalse($store->ignore('missing', 'no reason'));

        $recordFile = $directory . DIRECTORY_SEPARATOR . $record['id'] . '.json';
        touch($recordFile, time() - 10);
        self::assertContains($record['id'], $store->purgeCandidates(0));
    }

    public function testStorePayloadDisabledKeepsMetadataOnly(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['store_payload' => false]]);

        $record = $this->capture($config);

        self::assertIsArray($record);
        self::assertFalse($record['payload']['stored']);
        self::assertSame([], $record['payload']['fields']);
        self::assertArrayHasKey('verdict', $record);
        self::assertSame(1, \count($store->listRecords()));
    }

    public function testBinaryBodyAndInvalidUtf8FieldsAreStoredSafely(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $request = new RequestData(
            fields: [
                'bad' => "\xFF\xFE broken",
                'object' => new stdClass(),
                'empty' => '',
                'subscribe' => true,
                'none' => null,
            ],
            ip: '2001:db8::1',
            headers: ['host' => 'example.ru'],
            method: 'POST',
            uri: '/contact',
            body: "\x00\xFF binary payload",
            formId: 'lead',
        );

        $record = RejectedStore::capture($request, $config, $this->spamVerdict(), 'example.ru', 'lead');
        self::assertIsArray($record);
        self::assertSame('base64', $record['payload']['body_encoding']);
        self::assertSame('stdClass', $record['payload']['fields']['object']);
        self::assertSame('', $record['payload']['fields']['empty']);
        self::assertTrue($record['payload']['fields']['subscribe']);

        $raw = (string) file_get_contents($store->directory() . DIRECTORY_SEPARATOR . $record['id'] . '.json');
        $decoded = json_decode($raw, true);
        self::assertIsArray($decoded);
        self::assertTrue(mb_check_encoding((string) $decoded['payload']['fields']['bad'], 'UTF-8'));

        $masked = RejectedStore::maskRecord($record);
        self::assertSame('', $masked['payload']['fields']['empty']);
        self::assertSame('2001:db8::***', $masked['client']['ip']);

        $summary = $store->summarize($record);
        self::assertFalse($summary['has_email']);
        self::assertFalse($summary['has_phone']);
    }

    public function testNestedUploadsAreNormalisedAndEmptyEntriesSkipped(): void
    {
        $root = $this->tempDir();
        [$config] = $this->boot($root);
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'one.pdf';
        file_put_contents($upload, 'PDFDATA');

        $files = [
            'docs' => [
                'name' => ['one.pdf', ''],
                'type' => ['application/pdf', ''],
                'tmp_name' => [$upload, ''],
                'error' => [UPLOAD_ERR_OK, UPLOAD_ERR_NO_FILE],
                'size' => [7, 0],
            ],
        ];

        $record = $this->capture($config, files: $files);

        self::assertIsArray($record);
        self::assertCount(1, $record['payload']['files']);
        self::assertSame('docs[0]', $record['payload']['files'][0]['field']);
        self::assertSame(hash('sha256', 'PDFDATA'), $record['payload']['files'][0]['sha256']);
    }

    public function testEmptyUploadNameGetsAFallbackFileName(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['store_files' => true]]);
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'unnamed.bin';
        file_put_contents($upload, 'DATA');

        $record = $this->capture($config, files: [
            'document' => [
                'name' => '',
                'type' => 'application/octet-stream',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 4,
            ],
        ]);

        self::assertIsArray($record);
        self::assertTrue($record['payload']['files'][0]['stored']);
        self::assertStringEndsWith('upload.bin', (string) $record['payload']['files'][0]['stored_path']);
        self::assertFileExists(
            $store->directory() . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, (string) $record['payload']['files'][0]['stored_path']),
        );
    }

    public function testRetentionPurgesOldRecordsOnTheNextCapture(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $old = $this->capture($config);
        self::assertIsArray($old);
        touch($store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json', time() - 40 * 86400);

        $new = $this->capture($config);
        self::assertIsArray($new);

        self::assertFileDoesNotExist($store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json');
        self::assertFileExists($store->directory() . DIRECTORY_SEPARATOR . $new['id'] . '.json');
    }

    public function testRequestInfoIsDerivedFromServerWhenHeadersLackHost(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root);

        $request = new RequestData(
            fields: ['a' => 'b'],
            ip: '203.0.113.5',
            headers: ['user-agent' => 'UA'],
            query: [],
            method: 'POST',
            uri: '',
            formId: 'lead',
        );

        $record = RejectedStore::capture(
            $request,
            $config,
            $this->spamVerdict(),
            'example.ru',
            'lead',
            RejectedStore::REASON_SPAM,
            [
                'HTTP_HOST' => 'derived.example',
                'SERVER_NAME' => 'fallback.example',
                'HTTPS' => 'off',
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'QUERY_STRING' => 'a=1&b=2',
                'REQUEST_URI' => '/handled?a=1&b=2',
            ],
        );

        self::assertIsArray($record);
        self::assertSame('derived.example', $record['request']['host']);
        self::assertSame('https', $record['request']['scheme']);
        self::assertSame('/handled?a=1&b=2', $record['request']['uri']);
        self::assertSame(['a' => '1', 'b' => '2'], $record['request']['query']);
        self::assertSame('a=1&b=2', $record['request']['query_string']);
        self::assertSame('https://derived.example/handled?a=1&b=2', $record['request']['url']);

        // A non-scalar HTTP_HOST is ignored, SERVER_NAME is the fallback.
        $second = RejectedStore::capture(
            $request,
            $config,
            $this->spamVerdict(),
            'example.ru',
            'lead',
            RejectedStore::REASON_SPAM,
            ['HTTP_HOST' => ['broken'], 'SERVER_NAME' => 'fallback.example', 'REQUEST_URI' => '/x'],
        );
        self::assertIsArray($second);
        self::assertSame('fallback.example', $second['request']['host']);
        self::assertSame('http', $second['request']['scheme']);
    }

    public function testMinimalRecordFallbackForLongRequestMetadata(): void
    {
        $root = $this->tempDir();
        [$config, $store] = $this->boot($root, ['rejected' => ['max_bytes_per_record' => 1280]]);

        $request = new RequestData(
            fields: ['name' => 'John Smith'],
            ip: '203.0.113.77',
            headers: [
                'host' => 'example.ru',
                'user-agent' => str_repeat('A', 3000),
                'referer' => 'https://example.ru/contact/',
                'content-type' => 'application/x-www-form-urlencoded',
            ],
            method: 'POST',
            uri: '/contact',
            formId: 'lead',
        );

        $record = RejectedStore::capture($request, $config, $this->spamVerdict(), 'example.ru', 'lead');
        self::assertIsArray($record);
        self::assertTrue($record['truncated']);
        self::assertContains('payload', $record['truncated_fields']);
        self::assertSame('new', $record['status']);
        self::assertLessThanOrEqual(1280, (int) filesize($store->directory() . DIRECTORY_SEPARATOR . $record['id'] . '.json'));
    }

    public function testFirstReasonFallsBackToTheRecordReason(): void
    {
        $root = $this->tempDir();
        [$config] = $this->boot($root);

        $record = RejectedStore::capture(
            $this->request(),
            $config,
            new Verdict(Status::Spam, 60),
            'example.ru',
            'lead',
        );

        self::assertIsArray($record);
        self::assertSame([], RejectedStore::reasons($record));
        self::assertSame('spam', RejectedStore::firstReason($record));
    }

    /**
     * @param  array<string, mixed>                             $fields
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runGuardSubprocess(string $configDir, array $fields): array
    {
        $root = \dirname(__DIR__, 2);
        $script = $this->tempDir() . DIRECTORY_SEPARATOR . 'guard-runner.php';

        file_put_contents($script, "<?php\n"
            . 'require ' . var_export($root . DIRECTORY_SEPARATOR . 'autoload.php', true) . ";\n"
            . '$guard = FormSpamChecker\\Integration\\FormGuard::boot(' . var_export('guard', true)
            . ', ' . var_export($configDir, true) . ");\n"
            . "\$guard->run([\n"
            . "    'REQUEST_METHOD' => 'POST',\n"
            . "    'REQUEST_URI' => '/contact/',\n"
            . "    'REMOTE_ADDR' => '203.0.113.92',\n"
            . "    'HTTP_HOST' => 'guard.example',\n"
            . "    'HTTP_USER_AGENT' => " . var_export(self::UA, true) . ",\n"
            . "    'HTTP_ACCEPT' => 'application/json',\n"
            . '], ' . var_export($fields, true) . ");\n"
            . "echo 'PASSED';\n");

        return $this->runPhp($script);
    }

    /**
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runWafGuardSubprocess(string $configDir): array
    {
        $root = \dirname(__DIR__, 2);
        $script = $this->tempDir() . DIRECTORY_SEPARATOR . 'waf-guard-runner.php';

        file_put_contents($script, "<?php\n"
            . 'require ' . var_export($root . DIRECTORY_SEPARATOR . 'autoload.php', true) . ";\n"
            . '$guard = FormSpamChecker\\Integration\\WafGuard::boot(' . var_export('waf', true)
            . ', ' . var_export($configDir, true) . ");\n"
            . "\$guard->run([\n"
            . "    'REQUEST_METHOD' => 'POST',\n"
            . "    'REQUEST_URI' => '/api/lead',\n"
            . "    'REMOTE_ADDR' => '203.0.113.93',\n"
            . "    'HTTP_HOST' => 'waf.example',\n"
            . "    'CONTENT_TYPE' => 'application/x-www-form-urlencoded',\n"
            . "    'HTTP_USER_AGENT' => " . var_export(self::UA, true) . ",\n"
            . "], null, null, null, " . var_export('name=1 UNION SELECT password FROM users', true) . ");\n"
            . "echo 'PASSED';\n");

        return $this->runPhp($script);
    }

    /**
     * @return array{code: int, stdout: string, stderr: string}
     */
    private function runPhp(string $script): array
    {
        $root = \dirname(__DIR__, 2);
        $process = proc_open(
            [PHP_BINARY, $script],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $root,
        );

        self::assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return ['code' => proc_close($process), 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
    }
}
