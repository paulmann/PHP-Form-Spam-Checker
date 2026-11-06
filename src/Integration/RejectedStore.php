<?php

declare(strict_types=1);

namespace FormSpamChecker\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Waf\WafRequest;
use FormSpamChecker\Waf\WafVerdict;
use JsonException;
use Throwable;

/**
 * Registry of rejected ("unsent") form submissions.
 *
 * When the drop-in guard blocks a submission, the application never sees it and
 * the data is normally gone. This store persists one JSON record per rejected
 * submission — the full payload, the client and the exact rejection reason — so
 * that an operator can (a) see why a genuine lead was refused and (b) turn the
 * record into a real submission later ({@see ReplayRequest}).
 *
 * This is deliberately different from the pseudonymised verdict log
 * (`log.pii` stays `false`): the registry *does* store personal data, because a
 * record without the payload cannot be replayed. The access control is the
 * filesystem: the tree is created `0700`, every file is `0600`, a `.htaccess`
 * denies web access (Apache only — the directory must live outside the document
 * root) and `retention_days` deletes old records. A shared configuration
 * (`rejected.store_payload`, `rejected.store_files`,
 * `rejected.store_headers_secrets`) and the CLI's masked-by-default output
 * (`bin/rejected-forms show <id> --reveal` to override) keep routine inspection
 * from spraying personal data into terminals.
 *
 * Storage model: one file per record, `<id>.json`, written atomically
 * (temp file + rename). The id starts with the UTC timestamp and microseconds,
 * so lexicographic order is chronological order. Every public method is
 * fail-open: a registry problem is logged best-effort and never blocks or
 * breaks the form handler.
 */
final class RejectedStore
{
    public const string STATUS_NEW = 'new';
    public const string STATUS_REPLAYED = 'replayed';
    public const string STATUS_IGNORED = 'ignored';
    public const string STATUS_EXPIRED = 'expired';

    /** Why the submission was persisted. */
    public const string REASON_SPAM = 'spam';
    public const string REASON_WAF = 'waf';
    public const string REASON_SUSPICIOUS = 'suspicious';

    public const string SOURCE_FORM = 'form';
    public const string SOURCE_WAF = 'waf';

    /** Record schema version (bumped only on an incompatible change). */
    public const int VERSION = 1;

    private const string MARKER = '[truncated]';
    private const string RECORD_SUFFIX = '.json';
    private const int MIN_MAX_BYTES = 768;
    private const int MIN_MAX_RECORDS = 1;
    private const int MAX_FIELD_KEY_BYTES = 200;
    private const int MAX_HEADER_VALUE_BYTES = 4096;
    private const int MAX_FILES = 20;
    private const int MAX_SHA256_BYTES = 8388608;
    private const int MAX_TRUNCATED_NAMES = 50;

    /**
     * Headers that make a submission replayable. Everything else is dropped:
     * a form handler decides on Host, Content-Type, Accept and the referer,
     * and a registry should not hoard every intermediate-proxy header.
     *
     * @var list<string>
     */
    private const array REPLAY_HEADERS = [
        'host',
        'content-type',
        'user-agent',
        'referer',
        'origin',
        'accept',
        'accept-language',
        'x-requested-with',
    ];

    /**
     * Secrets never stored unless `rejected.store_headers_secrets` is enabled.
     * They are never replayed, with or without that flag.
     *
     * @var list<string>
     */
    private const array SECRET_HEADERS = [
        'cookie',
        'authorization',
        'proxy-authorization',
        'x-api-key',
    ];

    /**
     * @param string|null $directory explicit per-site registry directory (CLI and tests);
     *                               null derives it from configuration
     */
    public function __construct(
        private readonly Config $config,
        private readonly string $site,
        private readonly ?string $directory = null,
    ) {}

    /**
     * Persist one rejected submission.
     *
     * This is the entry point the guards use. It never throws: on any failure
     * the record is skipped and a line is written to `error_log`, because a
     * broken registry must not take a form down.
     *
     * @param  array<mixed>              $server superglobals the guard received
     * @param  array<mixed>              $files  $_FILES of the request
     * @return array<string, mixed>|null the stored record, or null when nothing was written
     */
    public static function capture(
        RequestData|WafRequest $request,
        Config $config,
        Verdict|WafVerdict $verdict,
        string $site,
        string $form,
        string $reason = self::REASON_SPAM,
        array $server = [],
        array $files = [],
        bool $wouldReject = true,
    ): ?array {
        try {
            if (!$config->bool('rejected.enabled', true)) {
                return null;
            }

            if (!self::isCapturable($verdict, $config)) {
                return null;
            }

            // A verdict that never blocked the request must not claim it would.
            $wouldReject = $wouldReject && self::isBlocking($verdict);

            return (new self($config, $site))->store(
                $request,
                $verdict,
                $form,
                $reason,
                $server,
                $files,
                $wouldReject,
            );
        } catch (Throwable $exception) {
            error_log('[rejected] capture failed (fail open): ' . $exception->getMessage());

            return null;
        }
    }

    public function site(): string
    {
        return $this->site;
    }

    public function enabled(): bool
    {
        return $this->config->bool('rejected.enabled', true);
    }

    /**
     * Directory this registry writes to: `rejected.path` when configured,
     * otherwise `<dirname(dirname(storage.path))>/rejected/<site>` — a
     * top-level tree next to `var/log`, not inside the per-site counter tree.
     */
    public function directory(): string
    {
        return $this->directory ?? self::directoryFor($this->config, $this->site);
    }

    /**
     * Registry directory for one site.
     *
     * With the shared guard the derived default is
     * `/var/www/lib/PHP-Form-Spam-Checker/var/rejected/<site>`; with an
     * unconfigured `storage.path` it is `<sys temp>/rejected/<site>`.
     */
    public static function directoryFor(Config $config, string $site): string
    {
        $configured = rtrim($config->string('rejected.path'), '/\\');

        if ($configured !== '') {
            return $configured;
        }

        $storage = rtrim($config->string('storage.path'), '/\\');

        if ($storage !== '') {
            // var/sites/<slug> -> var/rejected/<slug>
            $root = \dirname(\dirname($storage)) . DIRECTORY_SEPARATOR . 'rejected';
        } else {
            $root = \dirname(rtrim($config->storagePath(), '/\\')) . DIRECTORY_SEPARATOR . 'rejected';
        }

        return $root . DIRECTORY_SEPARATOR . self::slug($site);
    }

    /**
     * Records of this site, newest first.
     *
     * Supported filters: `status` (effective status), `form`, `since` (epoch
     * seconds), `limit` (default 200).
     *
     * @param  array<string, mixed>       $filters
     * @return list<array<string, mixed>>
     */
    public function listRecords(array $filters = []): array
    {
        $status = \is_string($filters['status'] ?? null) ? $filters['status'] : '';
        $form = \is_string($filters['form'] ?? null) ? $filters['form'] : '';
        $since = \is_int($filters['since'] ?? null) ? $filters['since'] : 0;
        $limit = \is_int($filters['limit'] ?? null) ? max(0, $filters['limit']) : 200;

        $files = $this->recordFiles();

        if ($files === []) {
            return [];
        }

        rsort($files, SORT_STRING);

        $records = [];
        $now = time();

        foreach ($files as $file) {
            if (\count($records) >= $limit) {
                break;
            }

            $record = $this->decodeFile($file);

            if ($record === null) {
                continue;
            }

            if ($status !== '' && $this->effectiveStatus($record, $now) !== $status) {
                continue;
            }

            if ($form !== '' && ($record['form'] ?? '') !== $form) {
                continue;
            }

            if ($since > 0) {
                $created = \is_int($record['ts_epoch'] ?? null) ? $record['ts_epoch'] : 0;

                if ($created < $since) {
                    continue;
                }
            }

            $records[] = $record;
        }

        return $records;
    }

    /**
     * Load one record by id, or null when it does not exist / is unreadable.
     *
     * @return array<string, mixed>|null
     */
    public function find(string $id): ?array
    {
        if (!self::isValidId($id)) {
            return null;
        }

        return $this->decodeFile($this->directory() . DIRECTORY_SEPARATOR . $id . self::RECORD_SUFFIX);
    }

    /**
     * Mark a record as ignored (an operator decided not to replay it).
     */
    public function ignore(string $id, string $reason): bool
    {
        return $this->update($id, static fn(array $record): array => array_merge($record, [
            'status' => self::STATUS_IGNORED,
            'ignored_at' => date('c'),
            'ignore_reason' => $reason,
        ]));
    }

    /**
     * Mark a record as replayed after a successful re-submission.
     */
    public function markReplayed(string $id, string $url, int $httpStatus): bool
    {
        return $this->update($id, static fn(array $record): array => array_merge($record, [
            'status' => self::STATUS_REPLAYED,
            'replayed_at' => date('c'),
            'replay_url' => $url,
            'replay_status' => $httpStatus,
        ]));
    }

    /**
     * Effective record status: a "new" record past its retention is presented
     * as "expired" before the physical purge removes it.
     *
     * @param array<string, mixed> $record
     */
    public function effectiveStatus(array $record, ?int $now = null): string
    {
        $status = \is_string($record['status'] ?? null) ? $record['status'] : self::STATUS_NEW;

        if ($status !== self::STATUS_NEW) {
            return $status;
        }

        $days = $this->retentionDays();
        $created = \is_int($record['ts_epoch'] ?? null) ? $record['ts_epoch'] : 0;

        if ($days > 0 && $created > 0 && ($now ?? time()) - $created > $days * 86400) {
            return self::STATUS_EXPIRED;
        }

        return $status;
    }

    /**
     * Ids that a purge with the given age would remove, newest-first order is
     * not needed: the CLI prints them sorted by id.
     *
     * @return list<string>
     */
    public function purgeCandidates(int $olderThanDays, ?int $now = null): array
    {
        $cutoff = ($now ?? time()) - max(0, $olderThanDays) * 86400;
        $ids = [];

        foreach ($this->recordFiles() as $file) {
            $mtime = @filemtime($file);

            if ($mtime !== false && $mtime < $cutoff) {
                $ids[] = basename($file, self::RECORD_SUFFIX);
            }
        }

        sort($ids);

        return $ids;
    }

    /**
     * Physically delete records older than the given number of days.
     *
     * @return list<string> deleted ids
     */
    public function purge(int $olderThanDays, ?int $now = null): array
    {
        $deleted = [];

        foreach ($this->purgeCandidates($olderThanDays, $now) as $id) {
            if (!self::isValidId($id)) {
                continue;
            }

            $file = $this->directory() . DIRECTORY_SEPARATOR . $id . self::RECORD_SUFFIX;

            if (@unlink($file)) {
                $deleted[] = $id;
            }
        }

        return $deleted;
    }

    /**
     * Public view of a record for `show` / `list`:
     * masked by default, fully revealable on purpose.
     *
     * @param  array<string, mixed> $record
     * @return array<string, mixed>
     */
    public static function maskRecord(array $record): array
    {
        $masked = $record;
        $client = \is_array($masked['client'] ?? null) ? $masked['client'] : [];
        $masked['client'] = [
            'ip' => self::maskIp(\is_string($client['ip'] ?? null) ? $client['ip'] : ''),
            'user_agent' => self::hidden(\is_string($client['user_agent'] ?? null) ? $client['user_agent'] : ''),
            'referer' => self::hidden(\is_string($client['referer'] ?? null) ? $client['referer'] : ''),
            'origin' => self::hidden(\is_string($client['origin'] ?? null) ? $client['origin'] : ''),
            'accept_language' => \is_string($client['accept_language'] ?? null) ? $client['accept_language'] : '',
        ];

        $request = \is_array($masked['request'] ?? null) ? $masked['request'] : [];
        $request['url'] = self::maskUrl(\is_string($request['url'] ?? null) ? $request['url'] : '');
        $headers = \is_array($request['headers'] ?? null) ? $request['headers'] : [];
        $maskedHeaders = [];
        foreach ($headers as $name => $value) {
            $lower = \is_string($name) ? strtolower($name) : '';
            $isPlain = \in_array($lower, ['host', 'content-type'], true);
            $maskedHeaders[$name] = $isPlain || !\is_string($value) ? $value : self::hidden($value);
        }
        $request['headers'] = $maskedHeaders;
        $masked['request'] = $request;

        $payload = \is_array($masked['payload'] ?? null) ? $masked['payload'] : [];
        $fields = \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [];
        $maskedFields = [];
        foreach ($fields as $name => $value) {
            $maskedFields[$name] = self::maskValue($value);
        }
        $payload['fields'] = $maskedFields;
        $payload['body'] = self::hidden(\is_string($payload['body'] ?? null) ? $payload['body'] : '');
        $files = \is_array($payload['files'] ?? null) ? $payload['files'] : [];
        $maskedFiles = [];
        foreach ($files as $file) {
            if (!\is_array($file)) {
                continue;
            }
            $entry = $file;
            $entry['name'] = self::hidden(\is_string($file['name'] ?? null) ? $file['name'] : '');
            unset($entry['stored_path']);
            $maskedFiles[] = $entry;
        }
        $payload['files'] = $maskedFiles;
        $masked['payload'] = $payload;

        $masked['personal_data'] = self::identifyPersonalData($fields);

        return $masked;
    }

    /**
     * Compact row for `list`: identifies the record without revealing values.
     *
     * @param  array<string, mixed> $record
     * @return array<string, mixed>
     */
    public function summarize(array $record): array
    {
        $fields = self::recordFields($record);
        $personal = self::identifyPersonalData($fields);
        $client = \is_array($record['client'] ?? null) ? $record['client'] : [];
        $verdict = \is_array($record['verdict'] ?? null) ? $record['verdict'] : [];
        $score = \is_int($verdict['score'] ?? null) ? $verdict['score'] : 0;

        return [
            'id' => \is_string($record['id'] ?? null) ? $record['id'] : '',
            'ts' => \is_string($record['ts'] ?? null) ? $record['ts'] : '',
            'ts_utc' => \is_string($record['ts_utc'] ?? null) ? $record['ts_utc'] : '',
            'status' => $this->effectiveStatus($record),
            'site' => \is_string($record['site'] ?? null) ? $record['site'] : $this->site,
            'form' => \is_string($record['form'] ?? null) ? $record['form'] : '',
            'source' => \is_string($record['source'] ?? null) ? $record['source'] : '',
            'reason' => \is_string($record['reason'] ?? null) ? $record['reason'] : '',
            'would_reject' => ($record['would_reject'] ?? true) === true,
            'score' => $score,
            'first_reason' => self::firstReason($record),
            'has_email' => $personal['has_email'],
            'has_phone' => $personal['has_phone'],
            'fields' => \count($fields),
            'client_ip' => self::maskIp(\is_string($client['ip'] ?? null) ? $client['ip'] : ''),
        ];
    }

    /**
     * @param  array<string, mixed>                    $fields
     * @return array{has_email: bool, has_phone: bool}
     */
    public static function identifyPersonalData(array $fields): array
    {
        $flat = [];
        self::flatten($fields, $flat, 0);

        $hasEmail = false;
        $hasPhone = false;

        foreach ($flat as $name => $value) {
            if (!$hasEmail && preg_match('/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/', $value) === 1) {
                $hasEmail = true;
            }

            if ($hasPhone) {
                continue;
            }

            $digits = preg_replace('/\D+/', '', $value) ?? '';
            $nameLooksLikePhone = preg_match('/phone|tel|mobile|моб|тел/i', $name) === 1;

            if (\strlen($digits) >= 10 || ($nameLooksLikePhone && \strlen($digits) >= 7)) {
                $hasPhone = true;
            }
        }

        return ['has_email' => $hasEmail, 'has_phone' => $hasPhone];
    }

    /**
     * First (most important) reason of a rejection, for triage.
     *
     * @param array<string, mixed> $record
     */
    public static function firstReason(array $record): string
    {
        $verdict = \is_array($record['verdict'] ?? null) ? $record['verdict'] : [];
        $reasons = \is_array($verdict['reasons'] ?? null) ? $verdict['reasons'] : [];

        foreach ($reasons as $reason) {
            if (\is_string($reason) && $reason !== '') {
                return $reason;
            }
        }

        return \is_string($record['reason'] ?? null) ? $record['reason'] : '';
    }

    /**
     * All rejection reasons of a record, for the replay confirmation output.
     *
     * @param  array<string, mixed> $record
     * @return list<string>
     */
    public static function reasons(array $record): array
    {
        $verdict = \is_array($record['verdict'] ?? null) ? $record['verdict'] : [];
        $reasons = \is_array($verdict['reasons'] ?? null) ? $verdict['reasons'] : [];
        $result = [];

        foreach ($reasons as $reason) {
            if (\is_string($reason) && $reason !== '') {
                $result[] = $reason;
            }
        }

        return $result;
    }

    /**
     * @return list<string>
     */
    public static function statuses(): array
    {
        return [self::STATUS_NEW, self::STATUS_REPLAYED, self::STATUS_IGNORED, self::STATUS_EXPIRED];
    }

    /**
     * @param Verdict|WafVerdict $verdict
     */
    private static function isCapturable(Verdict|WafVerdict $verdict, Config $config): bool
    {
        if (self::isBlocking($verdict)) {
            return true;
        }

        return self::isSuspicious($verdict) && $config->bool('rejected.capture_suspicious', false);
    }

    private static function isBlocking(Verdict|WafVerdict $verdict): bool
    {
        return $verdict instanceof WafVerdict ? $verdict->isBlocked() : $verdict->isSpam();
    }

    private static function isSuspicious(Verdict|WafVerdict $verdict): bool
    {
        return $verdict->isSuspicious();
    }

    /**
     * Persist one record. Called only through {@see self::capture()}.
     *
     * @param  array<mixed>              $server
     * @param  array<mixed>              $files
     * @return array<string, mixed>|null
     */
    private function store(
        RequestData|WafRequest $request,
        Verdict|WafVerdict $verdict,
        string $form,
        string $reason,
        array $server,
        array $files,
        bool $wouldReject,
    ): ?array {
        if (!$this->enabled()) {
            return null;
        }

        $directory = $this->directory();

        if (!$this->ensureDirectory($directory)) {
            return null;
        }

        $id = self::newId();
        $now = time();
        $payload = $this->buildPayload($request, $files, $id, $directory);
        $requestData = $this->buildRequestInfo($request, $server);

        $record = [
            'version' => self::VERSION,
            'id' => $id,
            'ts' => date('c', $now),
            'ts_utc' => gmdate('Y-m-d\TH:i:s\Z', $now),
            'ts_epoch' => $now,
            'status' => self::STATUS_NEW,
            'site' => $this->site,
            'form' => $form,
            'source' => $verdict instanceof WafVerdict ? self::SOURCE_WAF : self::SOURCE_FORM,
            'reason' => $reason,
            'would_reject' => $wouldReject,
            'verdict' => $this->verdictInfo($verdict),
            'request' => $requestData,
            'client' => [
                'ip' => $request->ip,
                'user_agent' => $requestData['headers']['user-agent'] ?? '',
                'referer' => $requestData['headers']['referer'] ?? '',
                'origin' => $requestData['headers']['origin'] ?? '',
                'accept_language' => $requestData['headers']['accept-language'] ?? '',
            ],
            'payload' => $payload,
            'truncated' => false,
            'truncated_fields' => [],
        ];

        $fitted = $this->fit($record, $this->maxBytesPerRecord());

        if ($fitted === null) {
            $this->removeStoredFiles($id, $directory);
            error_log('[rejected] record skipped: even the minimal form exceeds rejected.max_bytes_per_record');

            return null;
        }

        if (!$this->writeRecord($record['id'], $fitted, $directory)) {
            $this->removeStoredFiles($id, $directory);

            return null;
        }

        $this->prune($directory);
        $this->purgeExpired($directory);

        return $fitted;
    }

    /**
     * @param  array<mixed>                                                                                                                                                                          $files
     * @return array{stored: bool, content_type: string, body: string, body_encoding: string, body_bytes: int, body_sha256: string, fields: array<string, mixed>, files: list<array<string, mixed>>}
     */
    private function buildPayload(RequestData|WafRequest $request, array $files, string $id, string $directory): array
    {
        $storePayload = $this->config->bool('rejected.store_payload', true);
        $body = $request->body;
        $bodyBytes = \strlen($body);
        $bodyEncoding = 'utf-8';

        if ($body !== '' && !mb_check_encoding($body, 'UTF-8')) {
            $body = base64_encode($body);
            $bodyEncoding = 'base64';
        }

        $fields = $storePayload ? self::sanitizeFields($request->fields) : [];
        $fileRecords = $storePayload ? $this->storeFiles($files, $id, $directory) : [];

        return [
            'stored' => $storePayload,
            'content_type' => self::cleanString($request->header('content-type'), self::MAX_HEADER_VALUE_BYTES),
            'body' => $body,
            'body_encoding' => $bodyEncoding,
            'body_bytes' => $bodyBytes,
            'body_sha256' => $bodyBytes > 0 ? hash('sha256', $body) : '',
            'fields' => $fields,
            'files' => $fileRecords,
        ];
    }

    /**
     * Normalise `$_FILES` and, when configured, copy uploads next to the record.
     *
     * @param  array<mixed>               $files
     * @return list<array<string, mixed>>
     */
    private function storeFiles(array $files, string $id, string $directory): array
    {
        $storeCopies = $this->config->bool('rejected.store_files', false);
        $result = [];

        foreach (self::flattenFiles($files) as $entry) {
            if (\count($result) >= self::MAX_FILES) {
                break;
            }

            $name = self::cleanString($entry['name'], 200);
            $size = max(0, $entry['size']);
            $error = $entry['error'];
            $tmp = $entry['tmp'];

            if ($name === '' && $size === 0 && $error === UPLOAD_ERR_NO_FILE) {
                continue;
            }

            $recordEntry = [
                'field' => $entry['field'],
                'name' => $name,
                'type' => self::cleanString($entry['type'], 200),
                'size' => $size,
                'error' => $error,
                'sha256' => '',
                'stored' => false,
                'stored_path' => null,
            ];

            if ($tmp !== '' && is_file($tmp)) {
                $fileSize = @filesize($tmp);

                if ($fileSize !== false && $fileSize <= self::MAX_SHA256_BYTES) {
                    $hash = @hash_file('sha256', $tmp);
                    $recordEntry['sha256'] = \is_string($hash) ? $hash : '';
                }

                if ($storeCopies) {
                    $storedPath = $this->copyUpload($tmp, $name, $id, $directory);

                    if ($storedPath !== null) {
                        $recordEntry['stored'] = true;
                        $recordEntry['stored_path'] = $storedPath;
                    }
                }
            }

            $result[] = $recordEntry;
        }

        return $result;
    }

    /**
     * Copy one upload into `<registry>/<site>/files/<id>/`, atomically.
     */
    private function copyUpload(string $tmp, string $name, string $id, string $directory): ?string
    {
        $filesDirectory = $directory . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . $id;

        if (!is_dir($filesDirectory) && !@mkdir($filesDirectory, 0700, true) && !is_dir($filesDirectory)) {
            return null;
        }

        $safe = self::safeFileName($name);
        $target = $filesDirectory . DIRECTORY_SEPARATOR . $safe;
        $counter = 1;

        while (is_file($target)) {
            $target = $filesDirectory . DIRECTORY_SEPARATOR . $counter . '-' . $safe;
            $counter++;
        }

        if (!@copy($tmp, $target)) {
            return null;
        }

        @chmod($target, 0600);

        return implode('/', ['files', $id, basename($target)]);
    }

    /**
     * @param  array<mixed>                                                                               $files
     * @return list<array{field: string, name: string, type: string, size: int, error: int, tmp: string}>
     */
    private static function flattenFiles(array $files, string $prefix = ''): array
    {
        $result = [];

        foreach ($files as $field => $entry) {
            if (!\is_array($entry)) {
                continue;
            }

            $segment = \is_string($field) ? $field : (string) $field;
            $path = $prefix === '' ? $segment : $prefix . '[' . $segment . ']';
            $name = $entry['name'] ?? null;

            if (\is_array($name)) {
                $nested = [];

                foreach (array_keys($name) as $index) {
                    $nestedEntry = [];

                    foreach (['name', 'type', 'tmp_name', 'error', 'size'] as $key) {
                        $values = $entry[$key] ?? [];
                        $nestedEntry[$key] = \is_array($values) ? ($values[$index] ?? null) : null;
                    }

                    $nested[(string) $index] = $nestedEntry;
                }

                $result = [...$result, ...self::flattenFiles($nested, $path)];
                continue;
            }

            $result[] = [
                'field' => $path,
                'name' => \is_scalar($name) ? (string) $name : '',
                'type' => \is_scalar($entry['type'] ?? null) ? (string) $entry['type'] : '',
                'size' => is_numeric($entry['size'] ?? null) ? (int) $entry['size'] : 0,
                'error' => is_numeric($entry['error'] ?? null) ? (int) $entry['error'] : UPLOAD_ERR_NO_FILE,
                'tmp' => \is_scalar($entry['tmp_name'] ?? null) ? (string) $entry['tmp_name'] : '',
            ];
        }

        return $result;
    }

    /**
     * @param  array<mixed>                                                                                                                                                                   $server
     * @return array{method: string, uri: string, path: string, query: array<string, mixed>, query_string: string, scheme: string, host: string, url: string, headers: array<string, string>}
     */
    private function buildRequestInfo(RequestData|WafRequest $request, array $server): array
    {
        $headers = $this->replayHeaders($request);

        $host = $headers['host'] ?? self::serverString($server, 'HTTP_HOST');

        if ($host === '') {
            $host = self::serverString($server, 'SERVER_NAME');
        }

        $scheme = self::scheme($server);
        $method = strtoupper($request->method !== '' ? $request->method : 'POST');
        $uri = $request->uri !== '' ? $request->uri : self::serverString($server, 'REQUEST_URI');

        if ($uri === '') {
            $uri = '/';
        }

        $query = $request->query;

        if ($query === []) {
            $queryString = self::serverString($server, 'QUERY_STRING');

            if ($queryString !== '') {
                $parsed = [];
                parse_str($queryString, $parsed);
                $query = $parsed;
            }
        }

        $parsedQuery = parse_url($uri, PHP_URL_QUERY);
        $queryString = \is_string($parsedQuery) && $parsedQuery !== ''
            ? $parsedQuery
            : http_build_query($query);

        $path = parse_url($uri, PHP_URL_PATH);

        if (!\is_string($path) || $path === '') {
            $path = $uri;
        }

        return [
            'method' => $method,
            'uri' => self::cleanString($uri, 8192),
            'path' => self::cleanString($path, 2048),
            'query' => self::sanitizeFields(self::stringKeyed($query)),
            'query_string' => self::cleanString($queryString, 8192),
            'scheme' => $scheme,
            'host' => self::cleanString($host, 255),
            'url' => $host !== '' ? $scheme . '://' . $host . $uri : $uri,
            'headers' => $headers,
        ];
    }

    /**
     * @param  Verdict|WafVerdict   $verdict
     * @return array<string, mixed>
     */
    private function verdictInfo(Verdict|WafVerdict $verdict): array
    {
        $data = $verdict->toArray();
        $data['kind'] = $verdict instanceof WafVerdict ? self::SOURCE_WAF : self::SOURCE_FORM;

        return $data;
    }

    /**
     * Only replay-relevant headers are stored, and secrets only on request.
     *
     * @return array<string, string>
     */
    private function replayHeaders(RequestData|WafRequest $request): array
    {
        $storeSecrets = $this->config->bool('rejected.store_headers_secrets', false);
        $headers = [];

        foreach ($request->headers as $name => $value) {
            if ($value === '') {
                continue;
            }

            $lower = strtolower($name);
            $isReplay = \in_array($lower, self::REPLAY_HEADERS, true);
            $isSecret = \in_array($lower, self::SECRET_HEADERS, true);

            if ((!$isReplay && !$isSecret) || ($isSecret && !$storeSecrets)) {
                continue;
            }

            $headers[$lower] = self::cleanString($value, self::MAX_HEADER_VALUE_BYTES);
        }

        return $headers;
    }

    /**
     * Enforce `rejected.max_bytes_per_record` without producing invalid JSON.
     *
     * Truncation ladder: body down to 0, then field values down to 0 (keys are
     * kept), then optional blocks are dropped. The record is flagged
     * `truncated=true` and lists what was cut in `truncated_fields`. Returns
     * null when even the minimal record does not fit the configured limit —
     * writing corrupt or oversized JSON would be worse than skipping.
     *
     * @param  array<string, mixed>      $record
     * @return array<string, mixed>|null
     */
    private function fit(array $record, int $maxBytes): ?array
    {
        $encoded = $this->encode($record);

        if ($encoded === null) {
            return null;
        }

        if (\strlen($encoded) <= $maxBytes) {
            return $record;
        }

        $record['truncated'] = true;
        $payload = \is_array($record['payload'] ?? null) ? self::stringKeyed($record['payload']) : [];
        $body = \is_string($payload['body'] ?? null) ? $payload['body'] : '';
        $fields = \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [];

        foreach ([null, 4096, 1024, 256, 0] as $bodyCap) {
            foreach ([null, 8192, 2048, 512, 128, 32, 0] as $fieldCap) {
                $candidate = $record;
                $candidatePayload = $payload;
                $truncatedFields = [];

                if ($bodyCap !== null && \strlen($body) > $bodyCap) {
                    $candidatePayload['body'] = $bodyCap === 0
                        ? ''
                        : mb_strcut($body, 0, $bodyCap) . self::MARKER;
                    $truncatedFields[] = 'payload.body';
                }

                if ($fieldCap !== null) {
                    $truncatedNames = [];
                    $candidatePayload['fields'] = self::capFields($fields, $fieldCap, $truncatedNames);

                    if ($truncatedNames !== []) {
                        $truncatedFields = [
                            ...$truncatedFields,
                            ...\array_slice($truncatedNames, 0, self::MAX_TRUNCATED_NAMES),
                        ];
                    }
                }

                $candidate['payload'] = $candidatePayload;
                $candidate['truncated_fields'] = $truncatedFields;
                $encoded = $this->encode($candidate);

                if ($encoded !== null && \strlen($encoded) <= $maxBytes) {
                    return $candidate;
                }
            }
        }

        return $this->minimalRecord($record, $maxBytes);
    }

    /**
     * Last resort: keep identity + request line + one reason, drop payload and
     * check evidence.
     *
     * @param  array<string, mixed>      $record
     * @return array<string, mixed>|null
     */
    private function minimalRecord(array $record, int $maxBytes): ?array
    {
        $verdict = \is_array($record['verdict'] ?? null) ? self::stringKeyed($record['verdict']) : [];
        $reasons = \is_array($verdict['reasons'] ?? null) ? $verdict['reasons'] : [];
        $firstReason = '';

        foreach ($reasons as $reason) {
            if (\is_string($reason) && $reason !== '') {
                $firstReason = mb_strcut($reason, 0, 200);
                break;
            }
        }

        $request = \is_array($record['request'] ?? null) ? self::stringKeyed($record['request']) : [];

        $minimal = $record;
        $minimal['truncated'] = true;
        $minimal['truncated_fields'] = ['payload', 'verdict.checks', 'client', 'request.headers'];
        $minimal['verdict'] = [
            'kind' => \is_string($verdict['kind'] ?? null) ? $verdict['kind'] : self::SOURCE_FORM,
            'status' => \is_string($verdict['status'] ?? null) ? $verdict['status'] : '',
            'score' => \is_int($verdict['score'] ?? null) ? $verdict['score'] : 0,
            'reasons' => $firstReason === '' ? [] : [$firstReason],
            'checks' => [],
        ];
        $minimal['payload'] = [
            'stored' => false,
            'content_type' => '',
            'body' => '',
            'body_encoding' => 'utf-8',
            'body_bytes' => 0,
            'body_sha256' => '',
            'fields' => ['_truncated' => self::MARKER],
            'files' => [],
        ];
        $minimal['client'] = [
            'ip' => '',
            'user_agent' => '',
            'referer' => '',
            'origin' => '',
            'accept_language' => '',
        ];
        $request['headers'] = array_intersect_key(
            \is_array($request['headers'] ?? null) ? self::stringKeyed($request['headers']) : [],
            array_flip(['host', 'content-type']),
        );
        $request['uri'] = mb_strcut(\is_string($request['uri'] ?? null) ? $request['uri'] : '', 0, 512);
        $request['path'] = mb_strcut(\is_string($request['path'] ?? null) ? $request['path'] : '', 0, 512);
        $request['url'] = mb_strcut(\is_string($request['url'] ?? null) ? $request['url'] : '', 0, 768);
        $request['query'] = [];
        $request['query_string'] = mb_strcut(
            \is_string($request['query_string'] ?? null) ? $request['query_string'] : '',
            0,
            256,
        );
        $minimal['request'] = $request;

        $encoded = $this->encode($minimal);

        if ($encoded !== null && \strlen($encoded) <= $maxBytes) {
            return $minimal;
        }

        return null;
    }

    /**
     * @param  array<string, mixed> $fields
     * @param  list<string>         $truncated
     * @return array<string, mixed>
     */
    private static function capFields(array $fields, int $cap, array &$truncated, int $depth = 0, string $prefix = ''): array
    {
        if ($depth > 32) {
            return [];
        }

        $result = [];

        foreach ($fields as $name => $value) {
            $path = $prefix === '' ? $name : $prefix . '.' . $name;

            if (\is_array($value)) {
                $result[$name] = self::capFields(self::stringKeyed($value), $cap, $truncated, $depth + 1, $path);
                continue;
            }

            if (\is_string($value) && \strlen($value) > $cap) {
                $result[$name] = mb_strcut($value, 0, $cap) . self::MARKER;
                $truncated[] = $path;
                continue;
            }

            $result[$name] = $value;
        }

        return $result;
    }

    /**
     * @param  array<mixed>         $values
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $values): array
    {
        $typed = [];

        foreach ($values as $key => $value) {
            if (\is_string($key)) {
                $typed[$key] = $value;
            }
        }

        return $typed;
    }

    /**
     * Best-effort removal of uploads stored for a record that was not written.
     */
    private function removeStoredFiles(string $id, string $directory): void
    {
        $filesDirectory = $directory . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . $id;

        if (!is_dir($filesDirectory)) {
            return;
        }

        $entries = @scandir($filesDirectory);

        if ($entries !== false) {
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                @unlink($filesDirectory . DIRECTORY_SEPARATOR . $entry);
            }
        }

        @rmdir($filesDirectory);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function decodeFile(string $file): ?array
    {
        $raw = @file_get_contents($file);

        if ($raw === false) {
            return null;
        }

        try {
            $data = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!\is_array($data) || !\is_string($data['id'] ?? null)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * @param array<string, mixed> $record
     */
    private function writeRecord(string $id, array $record, string $directory): bool
    {
        $encoded = $this->encode($record);

        if ($encoded === null) {
            return false;
        }

        $target = $directory . DIRECTORY_SEPARATOR . $id . self::RECORD_SUFFIX;
        $tmp = $target . '.tmp.' . bin2hex(random_bytes(4));

        if (@file_put_contents($tmp, $encoded, LOCK_EX) === false) {
            return false;
        }

        @chmod($tmp, 0600);

        if (!@rename($tmp, $target)) {
            @unlink($tmp);

            return false;
        }

        @chmod($target, 0600);

        return true;
    }

    /**
     * @param callable(array<string, mixed>): array<string, mixed> $mutator
     */
    private function update(string $id, callable $mutator): bool
    {
        $record = $this->find($id);

        if ($record === null) {
            return false;
        }

        $updated = $mutator($record);

        return $this->writeRecord($id, $updated, $this->directory());
    }

    /**
     * @param array<string, mixed> $record
     */
    private function encode(array $record): ?string
    {
        try {
            return json_encode(
                $record,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $exception) {
            error_log('[rejected] cannot encode record: ' . $exception->getMessage());

            return null;
        }
    }

    private function ensureDirectory(string $directory): bool
    {
        $root = \dirname($directory);

        foreach ([$root, $directory] as $path) {
            if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) {
                error_log('[rejected] cannot create registry directory: ' . $path);

                return false;
            }

            @chmod($path, 0700);
        }

        $htaccess = $root . DIRECTORY_SEPARATOR . '.htaccess';

        if (!is_file($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                . "<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n",
                LOCK_EX,
            );
            @chmod($htaccess, 0600);
        }

        return true;
    }

    /**
     * Delete oldest records above `rejected.max_records_per_site`.
     */
    private function prune(string $directory): void
    {
        $max = max(self::MIN_MAX_RECORDS, $this->config->int('rejected.max_records_per_site', 2000));
        $files = $this->recordFiles($directory);

        $excess = \count($files) - $max;

        if ($excess <= 0) {
            return;
        }

        sort($files, SORT_STRING);

        foreach (\array_slice($files, 0, $excess) as $file) {
            @unlink($file);
        }
    }

    /**
     * Remove records older than `rejected.retention_days` (0 disables the TTL).
     */
    private function purgeExpired(string $directory): void
    {
        $days = $this->retentionDays();

        if ($days <= 0) {
            return;
        }

        $cutoff = time() - $days * 86400;

        foreach ($this->recordFiles($directory) as $file) {
            $mtime = @filemtime($file);

            if ($mtime !== false && $mtime < $cutoff) {
                @unlink($file);
            }
        }
    }

    /**
     * @return list<string>
     */
    private function recordFiles(?string $directory = null): array
    {
        $files = glob(($directory ?? $this->directory()) . DIRECTORY_SEPARATOR . '*' . self::RECORD_SUFFIX);

        if ($files === false) {
            return [];
        }

        $result = [];

        foreach ($files as $file) {
            if (self::isValidId(basename($file, self::RECORD_SUFFIX))) {
                $result[] = $file;
            }
        }

        return $result;
    }

    private function retentionDays(): int
    {
        return max(0, $this->config->int('rejected.retention_days', 30));
    }

    private function maxBytesPerRecord(): int
    {
        return max(self::MIN_MAX_BYTES, $this->config->int('rejected.max_bytes_per_record', 262144));
    }

    private static function newId(): string
    {
        $now = microtime(true);
        $seconds = (int) $now;
        $microseconds = (int) round(($now - $seconds) * 1_000_000);

        if ($microseconds > 999999) {
            $seconds++;
            $microseconds = 0;
        }

        return gmdate('Ymd\THis', $seconds)
            . \sprintf('%06d', $microseconds)
            . '-'
            . bin2hex(random_bytes(4));
    }

    private static function isValidId(string $id): bool
    {
        return $id !== ''
            && !str_contains($id, '..')
            && preg_match('/^[A-Za-z0-9][A-Za-z0-9._\-]{0,119}$/', $id) === 1;
    }

    private static function slug(string $site): string
    {
        $site = strtolower(trim($site));
        $site = preg_replace('#^www\.#', '', $site) ?? $site;
        $slug = preg_replace('/[^a-z0-9._-]+/', '_', $site);

        return $slug !== null && $slug !== '' ? $slug : 'default';
    }

    private static function safeFileName(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = preg_replace('/[^A-Za-z0-9._-]+/', '_', $name) ?? '';
        $name = ltrim($name, '.');

        if ($name === '') {
            return 'upload.bin';
        }

        return mb_strcut($name, 0, 120);
    }

    /**
     * @param  array<string, mixed> $fields
     * @return array<string, mixed>
     */
    private static function sanitizeFields(array $fields): array
    {
        $result = [];

        foreach ($fields as $key => $value) {
            $name = self::cleanString($key, self::MAX_FIELD_KEY_BYTES);
            $result[$name] = self::sanitizeValue($value, 0);
        }

        return $result;
    }

    private static function sanitizeValue(mixed $value, int $depth): mixed
    {
        if ($depth > 32) {
            return self::MARKER;
        }

        if (\is_string($value)) {
            return self::cleanString($value);
        }

        if (\is_int($value) || \is_float($value) || \is_bool($value) || $value === null) {
            return $value;
        }

        if (\is_array($value)) {
            $result = [];

            foreach ($value as $key => $item) {
                $name = \is_string($key) ? self::cleanString($key, self::MAX_FIELD_KEY_BYTES) : $key;
                $result[$name] = self::sanitizeValue($item, $depth + 1);
            }

            return $result;
        }

        return self::cleanString(get_debug_type($value));
    }

    private static function cleanString(string $value, ?int $maxBytes = null): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }

        if ($maxBytes !== null && \strlen($value) > $maxBytes) {
            $value = mb_strcut($value, 0, $maxBytes);
        }

        return $value;
    }

    /**
     * @param array<mixed> $server
     */
    private static function serverString(array $server, string $key): string
    {
        $value = $server[$key] ?? '';

        if (\is_array($value)) {
            return '';
        }

        return \is_scalar($value) ? trim((string) $value) : '';
    }

    /**
     * @param array<mixed> $server
     */
    private static function scheme(array $server): string
    {
        $https = $server['HTTPS'] ?? '';

        if ((!\is_string($https) && !\is_bool($https)) || ($https === '' || $https === 'off' || $https === '0' || $https === false)) {
            $forwarded = self::serverString($server, 'HTTP_X_FORWARDED_PROTO');

            return str_starts_with(strtolower($forwarded), 'https') ? 'https' : 'http';
        }

        return 'https';
    }

    /**
     * @param  array<string, mixed> $record
     * @return array<string, mixed>
     */
    private static function recordFields(array $record): array
    {
        $payload = \is_array($record['payload'] ?? null) ? self::stringKeyed($record['payload']) : [];
        $fields = \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [];

        return $fields;
    }

    /**
     * @param array<mixed>          $value
     * @param array<string, string> $flat
     */
    private static function flatten(array $value, array &$flat, int $depth, string $prefix = ''): void
    {
        if ($depth > 32) {
            return;
        }

        foreach ($value as $key => $item) {
            $segment = \is_string($key) ? $key : (string) $key;
            $name = $prefix === '' ? $segment : $prefix . '.' . $segment;

            if (\is_array($item)) {
                self::flatten($item, $flat, $depth + 1, $name);
                continue;
            }

            if (\is_scalar($item)) {
                $flat[$name] = \is_string($item) ? $item : (string) $item;
            }
        }
    }

    private static function maskValue(mixed $value): mixed
    {
        if (\is_array($value)) {
            $result = [];

            foreach ($value as $key => $item) {
                $result[$key] = self::maskValue($item);
            }

            return $result;
        }

        if ($value === null || $value === '') {
            return $value;
        }

        return self::hidden(\is_scalar($value) ? (string) $value : '');
    }

    private static function hidden(string $value): string
    {
        $length = mb_strlen($value);

        return $length === 0 ? '' : '[hidden ' . $length . ' chars]';
    }

    private static function maskIp(string $ip): string
    {
        if ($ip === '') {
            return '';
        }

        if (str_contains($ip, ':')) {
            $parts = explode(':', $ip);

            return implode(':', \array_slice($parts, 0, 2)) . '::***';
        }

        $parts = explode('.', $ip);

        if (\count($parts) === 4) {
            return $parts[0] . '.' . $parts[1] . '.***.***';
        }

        return self::hidden($ip);
    }

    private static function maskUrl(string $url): string
    {
        if ($url === '') {
            return '';
        }

        $query = parse_url($url, PHP_URL_QUERY);

        if (!\is_string($query) || $query === '') {
            return $url;
        }

        $base = explode('?', $url, 2)[0];

        return $base . '?[hidden]';
    }
}
