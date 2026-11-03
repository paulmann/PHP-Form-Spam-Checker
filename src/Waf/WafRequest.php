<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

/**
 * Immutable snapshot of one HTTP request as the WAF rules see it.
 *
 * Deliberately separate from {@see \FormSpamChecker\Data\RequestData}: the
 * firewall needs the raw body, cookies, hop-by-hop headers and the effective
 * content type, which a form submission never exposes. Everything here is
 * untrusted input; the object never mutates.
 *
 * Header names are lower-cased by {@see self::fromGlobals()} so a lookup never
 * depends on the casing a client used. Multipart and binary bodies are carried
 * verbatim for the protocol checks but are excluded from text scanning by
 * {@see self::scannableBody()}: uploaded file bytes are not prose.
 */
final readonly class WafRequest
{
    /**
     * Hard cap on the body read from php://input by {@see self::fromGlobals()}.
     *
     * A request body is attacker-controlled; reading an unbounded stream into
     * memory is a denial-of-service vector. The guard lowers this with
     * `waf.max_body_bytes`.
     */
    public const int DEFAULT_MAX_BODY_BYTES = 1048576;

    /**
     * @param array<string, string> $headers lower-case header names
     * @param array<string, string> $cookies
     * @param array<string, mixed>  $query
     * @param array<string, mixed>  $fields
     */
    public function __construct(
        public string $method = 'GET',
        public string $uri = '/',
        public string $ip = '',
        public string $body = '',
        public string $contentType = '',
        public int $contentLength = 0,
        public array $headers = [],
        public array $cookies = [],
        public array $query = [],
        public array $fields = [],
        public ?int $now = null,
        public string $formId = 'default',
    ) {
    }

    /**
     * Build a request snapshot from superglobals or from explicit arrays.
     *
     * `$body` and `$maxBodyBytes` are optional extras: when no body is passed
     * the raw body is read from php://input and capped, which is what a real
     * auto-prepend firewall needs. Tests and embedded callers pass the body
     * directly and keep the read deterministic.
     *
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $get
     * @param array<string, mixed>|null $post
     * @param array<string, mixed>|null $cookie
     */
    public static function fromGlobals(
        ?array $server = null,
        ?array $get = null,
        ?array $post = null,
        ?array $cookie = null,
        ?string $body = null,
        int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES,
    ): self {
        $server ??= $_SERVER;

        $headers = self::headers($server);
        $body ??= self::readBody($maxBodyBytes);
        $body = self::truncate($body, $maxBodyBytes);

        $contentType = $headers['content-type'] ?? '';
        $contentLength = strlen($body);

        if (isset($server['CONTENT_LENGTH']) && is_numeric($server['CONTENT_LENGTH'])) {
            $contentLength = (int) $server['CONTENT_LENGTH'];
        } elseif (isset($headers['content-length']) && is_numeric($headers['content-length'])) {
            $contentLength = (int) $headers['content-length'];
        }

        $query = $get;
        if ($query === null) {
            $query = [];
            $rawQuery = $server['QUERY_STRING'] ?? '';
            if (is_string($rawQuery) && $rawQuery !== '') {
                parse_str($rawQuery, $query);
            }
        }

        $cookies = [];
        foreach (($cookie ?? $_COOKIE) as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $cookies[$name] = $value;
            }
        }

        $fields = $post ?? $_POST;

        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        if ($uri === '') {
            $uri = '/';
        }

        return new self(
            method: strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
            uri: $uri,
            ip: self::clientIp($server),
            body: $body,
            contentType: $contentType,
            contentLength: $contentLength,
            headers: $headers,
            cookies: $cookies,
            query: $query,
            fields: $fields,
        );
    }

    /**
     * Case-insensitive header lookup; '' when the header is absent.
     */
    public function header(string $name): string
    {
        $key = strtolower($name);

        if (isset($this->headers[$key])) {
            return $this->headers[$key];
        }

        foreach ($this->headers as $headerName => $headerValue) {
            if (strtolower($headerName) === $key) {
                return $headerValue;
            }
        }

        return '';
    }

    public function hasHeader(string $name): bool
    {
        return $this->header($name) !== '';
    }

    /**
     * Scalar query parameter as a trimmed string; arrays become ''.
     */
    public function queryString(string $name): string
    {
        if (!array_key_exists($name, $this->query)) {
            return '';
        }

        $value = $this->query[$name];

        return match (true) {
            is_string($value) => trim($value),
            is_int($value), is_float($value) => (string) $value,
            is_bool($value) => $value ? '1' : '',
            default => '',
        };
    }

    public function userAgent(): string
    {
        return $this->header('user-agent');
    }

    /**
     * Path component of the request URI, without query string or fragment.
     */
    public function path(): string
    {
        $path = parse_url($this->uri, PHP_URL_PATH);

        if (is_string($path) && $path !== '') {
            return $path;
        }

        $fallback = explode('?', $this->uri, 2)[0];

        return $fallback === '' ? '/' : $fallback;
    }

    /**
     * Content type of the request body.
     *
     * The dedicated property is authoritative; the header is the fallback for
     * callers that build the snapshot from a header map only.
     */
    public function effectiveContentType(): string
    {
        return $this->contentType !== '' ? $this->contentType : $this->header('content-type');
    }

    /**
     * Declared body size: the property when set, otherwise Content-Length.
     */
    public function declaredContentLength(): int
    {
        if ($this->contentLength !== 0) {
            return $this->contentLength;
        }

        $header = $this->header('content-length');

        return $header !== '' && is_numeric($header) ? (int) $header : 0;
    }

    /**
     * True for multipart/form-data requests (file uploads).
     */
    public function isMultipart(): bool
    {
        return str_contains(strtolower($this->effectiveContentType()), 'multipart/');
    }

    /**
     * True when the body is not textual, so text signatures cannot be applied.
     */
    public function bodyIsBinary(): bool
    {
        if ($this->body === '') {
            return false;
        }

        if (str_contains($this->body, "\0")) {
            return true;
        }

        return !mb_check_encoding($this->body, 'UTF-8');
    }

    /**
     * Body text that a content rule may scan; '' when the body must be ignored.
     *
     * Uploaded files (multipart) and binary payloads are excluded on purpose:
     * a JPEG that happens to contain "or 1=1" is not an SQL injection.
     */
    public function scannableBody(): string
    {
        if ($this->body === '' || $this->isMultipart() || $this->bodyIsBinary()) {
            return '';
        }

        return $this->body;
    }

    public function timestamp(): int
    {
        return $this->now ?? time();
    }

    /**
     * @param array<string, mixed> $server
     * @return array<string, string>
     */
    private static function headers(array $server): array
    {
        $headers = [];

        foreach ($server as $key => $value) {
            if (!is_string($key) || !is_string($value) || $value === '') {
                continue;
            }

            if (str_starts_with($key, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
                continue;
            }

            if ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                $headers[strtolower(str_replace('_', '-', $key))] = $value;
            }
        }

        return $headers;
    }

    /**
     * @param array<string, mixed> $server
     */
    private static function clientIp(array $server): string
    {
        $ip = '';

        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
            if (isset($server[$key]) && is_string($server[$key]) && trim($server[$key]) !== '') {
                $ip = trim($server[$key]);
                break;
            }
        }

        // X-Forwarded-For is only honoured behind a local reverse proxy:
        // otherwise any client could choose its own address.
        if (isset($server['HTTP_X_FORWARDED_FOR']) && is_string($server['HTTP_X_FORWARDED_FOR'])) {
            $remote = (string) ($server['REMOTE_ADDR'] ?? '');

            if ($remote === '::1' || str_starts_with($remote, '127.') || str_starts_with($remote, '::ffff:127.')) {
                $first = trim(explode(',', $server['HTTP_X_FORWARDED_FOR'])[0]);

                if (filter_var($first, FILTER_VALIDATE_IP) !== false) {
                    $ip = $first;
                }
            }
        }

        return $ip;
    }

    private static function readBody(int $maxBodyBytes): string
    {
        $cap = max(0, $maxBodyBytes);

        if ($cap === 0) {
            return '';
        }

        $raw = @file_get_contents('php://input', false, null, 0, $cap + 1);

        if (!is_string($raw)) {
            return '';
        }

        return strlen($raw) > $cap ? substr($raw, 0, $cap) : $raw;
    }

    private static function truncate(string $body, int $maxBodyBytes): string
    {
        $cap = max(0, $maxBodyBytes);

        if ($cap === 0) {
            return '';
        }

        return strlen($body) > $cap ? substr($body, 0, $cap) : $body;
    }
}
