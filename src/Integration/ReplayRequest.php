<?php

declare(strict_types=1);

namespace FormSpamChecker\Integration;

use Closure;
use InvalidArgumentException;
use RuntimeException;

/**
 * Replayable reconstruction of one {@see RejectedStore} record.
 *
 * A rejected submission is only useful if it can become a real one. This class
 * rebuilds the original request from the stored record — method, URL (scheme +
 * host + URI from the record), content type and body, plus the headers a form
 * handler actually looks at — and can perform it through a PHP stream context.
 *
 * Safety rules, all deliberate:
 *  - the target defaults to the record's own URL; a different host needs an
 *    explicit `--allow-host-change` because replaying personal data to the
 *    wrong server is a data leak;
 *  - Cookie/Authorization are never replayed, even if an operator stored them;
 *  - a replay without `confirm: true` only returns the plan — sending must be
 *    requested explicitly (the CLI requires `--confirm`);
 *  - uploads are replayed as `multipart/form-data` only when their bytes were
 *    stored (`rejected.store_files`); otherwise the replay refuses instead of
 *    silently sending a submission without its attachments.
 */
final readonly class ReplayRequest
{
    /**
     * Headers copied from the record when they exist.
     *
     * @var list<string>
     */
    private const array REPLAY_HEADERS = [
        'user-agent',
        'referer',
        'origin',
        'accept',
        'accept-language',
        'x-requested-with',
    ];

    /**
     * @param array<string, string>                                            $headers
     * @param list<array{name: string, type: string, size: int, path: string}> $files
     * @param list<string>                                                     $warnings
     */
    public function __construct(
        public string $method,
        public string $url,
        public array $headers,
        public string $body,
        public string $contentType = '',
        public array $files = [],
        public array $warnings = [],
    ) {}

    /**
     * Build the replay from a stored record.
     *
     * @param  array<string, mixed>     $record        a record as stored by RejectedStore
     * @param  string|null              $url           explicit target; null = the record's URL
     * @param  string|null              $baseDirectory registry site directory (needed for stored uploads)
     * @throws InvalidArgumentException when the record cannot be replayed safely
     */
    public static function fromRecord(array $record, ?string $url = null, ?string $baseDirectory = null): self
    {
        $target = $url !== null && $url !== '' ? $url : self::originalUrl($record);

        if ($target === '') {
            throw new InvalidArgumentException('The record has no request URL; pass --url=');
        }

        $scheme = strtolower((string) parse_url($target, PHP_URL_SCHEME));

        if (!\in_array($scheme, ['http', 'https'], true)) {
            throw new InvalidArgumentException('Replay URL must use http or https: ' . $target);
        }

        $request = \is_array($record['request'] ?? null) ? self::stringKeyed($record['request']) : [];
        $payload = \is_array($record['payload'] ?? null) ? self::stringKeyed($record['payload']) : [];
        $method = strtoupper(\is_string($request['method'] ?? null) ? $request['method'] : 'POST');

        if (!\in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            throw new InvalidArgumentException('Only POST, PUT and PATCH requests can be replayed, "'
                . $method . '" was recorded.');
        }

        $headers = self::replayHeaders($record);
        $storedFiles = self::storedFiles($payload, $baseDirectory);
        $fileMetadata = \is_array($payload['files'] ?? null) ? $payload['files'] : [];
        $warnings = [];

        if (($record['truncated'] ?? false) === true) {
            $warnings[] = 'The stored record is truncated: the replay may not match the original submission exactly.';
        }

        if (($payload['stored'] ?? true) !== true) {
            throw new InvalidArgumentException(
                'The payload was not stored for this record (rejected.store_payload=false); nothing to replay.',
            );
        }

        if ($fileMetadata !== [] && $storedFiles === []) {
            throw new InvalidArgumentException(
                'The submission had uploaded files but their bytes were not stored '
                . '(rejected.store_files=false); replaying without them would send an incomplete submission.',
            );
        }

        if ($storedFiles !== []) {
            $boundary = '----FormSpamCheckerReplay' . bin2hex(random_bytes(12));
            $fields = \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [];
            $body = self::multipartBody($fields, $storedFiles, $boundary);
            $contentType = 'multipart/form-data; boundary=' . $boundary;

            return new self(
                method: $method,
                url: $target,
                headers: $headers + [
                    'Content-Type' => $contentType,
                    'Content-Length' => (string) \strlen($body),
                    'Connection' => 'close',
                ],
                body: $body,
                contentType: $contentType,
                files: $storedFiles,
                warnings: $warnings,
            );
        }

        $body = http_build_query(
            \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [],
            '',
            '&',
            PHP_QUERY_RFC1738,
        );

        $contentType = 'application/x-www-form-urlencoded';

        return new self(
            method: $method,
            url: $target,
            headers: $headers + [
                'Content-Type' => $contentType,
                'Content-Length' => (string) \strlen($body),
                'Connection' => 'close',
            ],
            body: $body,
            contentType: $contentType,
            files: [],
            warnings: $warnings,
        );
    }

    /**
     * URL of the original request as recorded.
     *
     * @param array<string, mixed> $record
     */
    public static function originalUrl(array $record): string
    {
        $request = \is_array($record['request'] ?? null) ? $record['request'] : [];
        $url = $request['url'] ?? '';

        if (\is_string($url) && $url !== '') {
            return $url;
        }

        $host = \is_string($request['host'] ?? null) ? $request['host'] : '';
        $uri = \is_string($request['uri'] ?? null) ? $request['uri'] : '';
        $scheme = \is_string($request['scheme'] ?? null) && $request['scheme'] !== ''
            ? $request['scheme']
            : 'https';

        if ($host === '') {
            return $uri;
        }

        return $scheme . '://' . $host . $uri;
    }

    /**
     * Lower-cased host of an absolute URL; '' when it cannot be parsed.
     */
    public static function hostOf(string $url): string
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (!\is_string($host) || $host === '') {
            return '';
        }

        return strtolower(rtrim($host, '.'));
    }

    /**
     * Validate the replay target against the record.
     *
     * @param  array<string, mixed> $record
     * @return string|null          a human-readable reason to refuse, or null when allowed
     */
    public static function checkTarget(array $record, ?string $url, bool $allowHostChange): ?string
    {
        $originalHost = self::hostOf(self::originalUrl($record));
        $target = $url !== null && $url !== '' ? $url : self::originalUrl($record);

        if ($target === '') {
            return 'The record has no request URL; pass --url=';
        }

        $targetHost = self::hostOf($target);

        if ($targetHost === '') {
            return 'Replay URL has no host: ' . $target;
        }

        if ($originalHost !== '' && $targetHost !== $originalHost && !$allowHostChange) {
            return \sprintf(
                'Refusing to replay to a different host: target "%s", record "%s". '
                . 'Pass --allow-host-change to override.',
                $targetHost,
                $originalHost,
            );
        }

        return null;
    }

    /**
     * What would be sent; safe to print.
     *
     * @return array<string, mixed>
     */
    public function preview(): array
    {
        return [
            'sent' => false,
            'confirmed' => false,
            'method' => $this->method,
            'url' => $this->url,
            'content_type' => $this->contentType,
            'headers' => $this->headers,
            'body_bytes' => \strlen($this->body),
            'body_preview' => mb_strcut($this->body, 0, 1200),
            'files' => array_map(
                static fn(array $file): array => ['name' => $file['name'], 'size' => $file['size'], 'type' => $file['type']],
                $this->files,
            ),
            'warnings' => $this->warnings,
        ];
    }

    /**
     * Dry-run by default: only an explicit `confirm: true` sends anything.
     *
     * @return array<string, mixed>
     */
    public function replay(bool $confirm = false): array
    {
        if (!$confirm) {
            return $this->preview();
        }

        return $this->send();
    }

    /**
     * Perform the request with a stream context and report the HTTP result.
     *
     * The transport is injectable so a caller (and the test suite) can exercise
     * the response parsing without a network round-trip; production passes null
     * and the request goes through `file_get_contents()`.
     *
     * @param  (Closure(): array{0: string|false, 1: list<string>})|null             $transport
     * @return array{sent: bool, ok: bool, status: int, body: string, error: string}
     */
    public function send(float $timeout = 10.0, ?Closure $transport = null): array
    {
        $lines = [];

        foreach ($this->headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        $context = stream_context_create([
            'http' => [
                'method' => $this->method,
                'header' => implode("\r\n", $lines),
                'content' => $this->body,
                'timeout' => $timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 1,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        if ($transport !== null) {
            [$body, $responseHeaders] = $transport();
        } else {
            $body = @file_get_contents($this->url, false, $context);
            // PHP 8.5 deprecates the magic $http_response_header variable.
            $responseHeaders = http_get_last_response_headers() ?? [];
        }

        $status = 0;

        foreach ($responseHeaders as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                $status = (int) $matches[1];
                break;
            }
        }

        $error = '';

        if ($body === false && $status === 0) {
            $lastError = error_get_last();
            $error = $lastError !== null ? $lastError['message'] : 'transport error';
        }

        return [
            'sent' => true,
            'ok' => $status >= 200 && $status < 400,
            'status' => $status,
            'body' => mb_strcut($body === false ? '' : $body, 0, 2000),
            'error' => $error,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'method' => $this->method,
            'url' => $this->url,
            'content_type' => $this->contentType,
            'headers' => $this->headers,
            'body_bytes' => \strlen($this->body),
            'body_preview' => mb_strcut($this->body, 0, 1200),
            'files' => $this->files,
            'warnings' => $this->warnings,
        ];
    }

    /**
     * @param  array<string, mixed>  $record
     * @return array<string, string>
     */
    private static function replayHeaders(array $record): array
    {
        $request = \is_array($record['request'] ?? null) ? $record['request'] : [];
        $stored = \is_array($request['headers'] ?? null) ? $request['headers'] : [];
        $headers = [];

        foreach ($stored as $name => $value) {
            if (!\is_string($name) || !\is_string($value) || $value === '') {
                continue;
            }

            $lower = strtolower($name);

            // Secrets are never replayed, whatever was stored for inspection.
            if (\in_array($lower, ['cookie', 'authorization', 'proxy-authorization', 'x-api-key', 'host', 'content-type', 'content-length'], true)) {
                continue;
            }

            if (!\in_array($lower, self::REPLAY_HEADERS, true)) {
                continue;
            }

            $headers[ucwords($lower, '-')] = $value;
        }

        return $headers;
    }

    /**
     * @param  array<string, mixed>                                             $payload
     * @throws InvalidArgumentException                                         when a stored upload escapes the registry tree or is missing
     * @return list<array{name: string, type: string, size: int, path: string}>
     */
    private static function storedFiles(array $payload, ?string $baseDirectory): array
    {
        $files = \is_array($payload['files'] ?? null) ? $payload['files'] : [];
        $stored = [];

        foreach ($files as $file) {
            if (!\is_array($file) || ($file['stored'] ?? false) !== true) {
                continue;
            }

            if ($baseDirectory === null || $baseDirectory === '') {
                throw new InvalidArgumentException(
                    'The record has stored uploads; replay needs the registry directory (pass --site/--path).',
                );
            }

            $relative = \is_string($file['stored_path'] ?? null) ? $file['stored_path'] : '';

            if ($relative === '') {
                continue;
            }

            $path = self::resolveStoredPath($baseDirectory, $relative);

            if ($path === null) {
                throw new InvalidArgumentException('Stored upload is missing or outside the registry tree: ' . $relative);
            }

            $stored[] = [
                'name' => \is_string($file['name'] ?? null) ? $file['name'] : 'upload.bin',
                'type' => \is_string($file['type'] ?? null) && $file['type'] !== ''
                    ? $file['type']
                    : 'application/octet-stream',
                'size' => \is_int($file['size'] ?? null) ? $file['size'] : 0,
                'path' => $path,
            ];
        }

        return $stored;
    }

    private static function resolveStoredPath(string $baseDirectory, string $relative): ?string
    {
        if (str_contains($relative, '..')) {
            return null;
        }

        $base = realpath($baseDirectory);
        $path = realpath($baseDirectory . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));

        if ($base === false || $path === false) {
            return null;
        }

        $prefix = rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        return str_starts_with($path, $prefix) ? $path : null;
    }

    /**
     * @param array<string, mixed>                                             $fields
     * @param list<array{name: string, type: string, size: int, path: string}> $files
     */
    private static function multipartBody(array $fields, array $files, string $boundary): string
    {
        $body = '';

        foreach (self::flattenFields($fields) as [$name, $value]) {
            $body .= '--' . $boundary . "\r\n"
                . 'Content-Disposition: form-data; name="' . self::quote($name) . '"' . "\r\n\r\n"
                . $value . "\r\n";
        }

        foreach ($files as $file) {
            $contents = @file_get_contents($file['path']);

            if ($contents === false) {
                throw new RuntimeException('Cannot read stored upload: ' . $file['path']);
            }

            $body .= '--' . $boundary . "\r\n"
                . 'Content-Disposition: form-data; name="file"; filename="' . self::quote($file['name']) . '"' . "\r\n"
                . 'Content-Type: ' . $file['type'] . "\r\n\r\n"
                . $contents . "\r\n";
        }

        return $body . '--' . $boundary . "--\r\n";
    }

    /**
     * @param  array<string, mixed>              $fields
     * @return list<array{0: string, 1: string}>
     */
    private static function flattenFields(array $fields, string $prefix = ''): array
    {
        $result = [];

        foreach ($fields as $name => $value) {
            $path = $prefix === '' ? $name : $prefix . '[' . $name . ']';

            if (\is_array($value)) {
                $result = [...$result, ...self::flattenFields(self::stringKeyed($value), $path)];
                continue;
            }

            if (\is_scalar($value) && $value !== false) {
                $result[] = [$path, \is_string($value) ? $value : (string) $value];
            }
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

    private static function quote(string $value): string
    {
        return str_replace(['"', "\r", "\n"], ['%22', '', ''], $value);
    }
}
