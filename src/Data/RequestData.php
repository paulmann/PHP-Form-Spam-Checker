<?php

declare(strict_types=1);

namespace FormSpamChecker\Data;

use NoDiscard;

/**
 * Immutable snapshot of one request as the checks see it.
 *
 * Everything here is untrusted input. The object never mutates: `withFields()`
 * and `withFormId()` return new instances and are marked `#[\NoDiscard]` so a
 * forgotten assignment is reported by PHP instead of silently losing the change.
 */
final readonly class RequestData
{
    /**
     * @param array<string, mixed>  $fields
     * @param array<string, string> $headers lower-case header names
     * @param array<string, string> $cookies
     * @param array<string, mixed>  $query
     */
    public function __construct(
        public array $fields = [],
        public string $ip = '',
        public array $headers = [],
        public array $cookies = [],
        public array $query = [],
        public string $method = 'POST',
        public string $uri = '',
        public string $body = '',
        public ?int $now = null,
        public string $formId = 'default',
    ) {}

    public function hasField(string $name): bool
    {
        return \array_key_exists($name, $this->fields);
    }

    /**
     * Scalar field value as a trimmed string; arrays/objects become ''.
     */
    public function field(string $name): string
    {
        if (!\array_key_exists($name, $this->fields)) {
            return '';
        }

        $value = $this->fields[$name];

        return match (true) {
            \is_string($value) => trim($value),
            \is_int($value), \is_float($value) => (string) $value,
            \is_bool($value) => $value ? '1' : '',
            default => '',
        };
    }

    /**
     * @param  list<string>          $exclude
     * @return array<string, string>
     */
    public function content(array $exclude = []): array
    {
        $flip = array_fill_keys($exclude, true);
        $result = [];

        foreach ($this->fields as $name => $value) {
            if (isset($flip[$name])) {
                continue;
            }

            if (\is_string($value)) {
                $trimmed = trim($value);
                if ($trimmed !== '') {
                    $result[$name] = $trimmed;
                }
                continue;
            }

            if (\is_int($value) || \is_float($value)) {
                $result[$name] = (string) $value;
            }
        }

        return $result;
    }

    /**
     * @param list<string> $exclude
     */
    public function text(array $exclude = []): string
    {
        return implode("\n", $this->content($exclude));
    }

    /**
     * Case-insensitive header lookup.
     */
    public function header(string $name): string
    {
        $key = strtolower($name);

        foreach ($this->headers as $headerName => $headerValue) {
            if (strtolower($headerName) === $key) {
                return $headerValue;
            }
        }

        return '';
    }

    public function userAgent(): string
    {
        return $this->header('user-agent');
    }

    /**
     * First non-empty value among the given field names.
     *
     * @param list<string> $fields
     */
    public function first(array $fields): string
    {
        foreach ($fields as $field) {
            $value = $this->field($field);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * Truncated, single-line field samples for privacy-aware logs.
     *
     * @param  list<string>          $exclude
     * @return array<string, string>
     */
    public function sample(array $exclude = [], int $limit = 120): array
    {
        $sample = [];
        foreach ($this->content($exclude) as $name => $value) {
            $single = preg_replace('/\s+/u', ' ', $value) ?? $value;
            $sample[$name] = mb_substr($single, 0, $limit);
        }

        return $sample;
    }

    public function referer(): string
    {
        return $this->header('referer');
    }

    public function timestamp(): int
    {
        return $this->now ?? time();
    }

    /**
     * @param array<string, mixed> $fields
     */
    #[NoDiscard]
    public function withFields(array $fields): self
    {
        return new self(
            $fields,
            $this->ip,
            $this->headers,
            $this->cookies,
            $this->query,
            $this->method,
            $this->uri,
            $this->body,
            $this->now,
            $this->formId,
        );
    }

    #[NoDiscard]
    public function withFormId(string $formId): self
    {
        return new self(
            $this->fields,
            $this->ip,
            $this->headers,
            $this->cookies,
            $this->query,
            $this->method,
            $this->uri,
            $this->body,
            $this->now,
            $formId,
        );
    }

    /**
     * Build the request snapshot from PHP superglobals (or from explicit arrays).
     *
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $post
     */
    public static function fromGlobals(?array $server = null, ?array $post = null, string $formId = 'default'): self
    {
        if ($server === null) {
            /** @var array<string, mixed> $server */
            $server = $_SERVER;
        }

        if ($post === null) {
            /** @var array<string, mixed> $post */
            $post = $_POST;
        }

        $headers = [];
        foreach ($server as $key => $value) {
            if (!\is_string($value)) {
                continue;
            }

            if (str_starts_with($key, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            } elseif (\in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true)) {
                $headers[strtolower(str_replace('_', '-', $key))] = $value;
            }
        }

        $ip = '';
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
            if (isset($server[$key]) && \is_string($server[$key]) && trim($server[$key]) !== '') {
                $ip = trim($server[$key]);
                break;
            }
        }

        if (!isset($server['HTTP_CF_CONNECTING_IP']) && isset($server['HTTP_X_FORWARDED_FOR']) && \is_string($server['HTTP_X_FORWARDED_FOR'])) {
            $remote = $server['REMOTE_ADDR'] ?? '';
            if (!\is_string($remote)) {
                $remote = '';
            }
            if (self::isLoopback($remote)) {
                $first = trim(explode(',', $server['HTTP_X_FORWARDED_FOR'])[0]);
                if (filter_var($first, FILTER_VALIDATE_IP) !== false) {
                    $ip = $first;
                }
            }
        }

        $query = [];
        if (isset($server['QUERY_STRING']) && \is_string($server['QUERY_STRING']) && $server['QUERY_STRING'] !== '') {
            $parsedQuery = [];
            parse_str($server['QUERY_STRING'], $parsedQuery);
            foreach ($parsedQuery as $queryKey => $queryValue) {
                if (\is_string($queryKey)) {
                    $query[$queryKey] = $queryValue;
                }
            }
        }

        $cookies = [];
        foreach ($_COOKIE as $cookieName => $cookieValue) {
            if (\is_string($cookieName) && \is_string($cookieValue)) {
                $cookies[$cookieName] = $cookieValue;
            }
        }

        $method = $server['REQUEST_METHOD'] ?? 'POST';
        if (!\is_string($method) || $method === '') {
            $method = 'POST';
        }

        $uri = $server['REQUEST_URI'] ?? '';
        if (!\is_string($uri)) {
            $uri = '';
        }

        return new self(
            fields: $post,
            ip: $ip,
            headers: $headers,
            cookies: $cookies,
            query: $query,
            method: strtoupper($method),
            uri: $uri,
            body: '',
            formId: $formId,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'fields' => $this->fields,
            'ip' => $this->ip,
            'headers' => $this->headers,
            'cookies' => $this->cookies,
            'query' => $this->query,
            'method' => $this->method,
            'uri' => $this->uri,
            'now' => $this->timestamp(),
            'formId' => $this->formId,
        ];
    }

    private static function isLoopback(string $ip): bool
    {
        return $ip !== ''
            && ($ip === '::1' || str_starts_with($ip, '127.') || str_starts_with($ip, '::ffff:127.'));
    }
}
