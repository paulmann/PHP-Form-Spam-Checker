<?php

declare(strict_types=1);

namespace FormSpamChecker\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\SpamChecker;
use RuntimeException;
use Throwable;

/**
 * Drop-in guard for existing PHP sites, loaded from the shared module
 * directory (/var/www/lib/PHP-Form-Spam-Checker).
 *
 * A site only needs one line at the top of its form handler:
 *
 *     require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
 *
 * and a per-site configuration file `config/sites/<host>.php`. The guard
 * ignores everything that is not a matching POST request, so including it in a
 * front controller is safe: static pages, GET requests and admin URLs pass
 * through untouched.
 *
 * Modes: off (nothing runs), shadow (verdict computed and logged, request
 * always passes), enforce (spam is answered and the application never sees it).
 */
final class FormGuard
{
    public const string MODE_OFF = 'off';
    public const string MODE_SHADOW = 'shadow';
    public const string MODE_ENFORCE = 'enforce';

    /**
     * @var array<string, array{mtime: int, data: array<string, mixed>}>
     */
    private static array $cache = [];

    /**
     * @param list<string> $match regexes; empty means "any POST request"
     * @param list<string> $skip  regexes that always pass through
     */
    private function __construct(
        private readonly string $site,
        private readonly string $mode,
        private readonly array $match,
        private readonly array $skip,
        private readonly string $formId,
        private readonly string $responseType,
        private readonly SpamChecker $checker,
        private readonly Config $config,
    ) {}

    public static function boot(?string $site = null, ?string $configDir = null): self
    {
        $configDir ??= \dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'sites';
        $site ??= self::detectSite();

        $file = $configDir . DIRECTORY_SEPARATOR . self::slug($site) . '.php';

        if (!is_file($file)) {
            $file = $configDir . DIRECTORY_SEPARATOR . 'default.php';
        }

        if (!is_file($file)) {
            return self::disabled($site);
        }

        try {
            $raw = self::loadConfigFile($file);
        } catch (Throwable $exception) {
            error_log(\sprintf('[spam-guard] cannot load config %s: %s', $file, $exception->getMessage()));

            return self::disabled($site);
        }

        if (!\is_array($raw)) {
            error_log(\sprintf('[spam-guard] config %s must return an array', $file));

            return self::disabled($site);
        }

        $modeValue = $raw['mode'] ?? self::MODE_OFF;
        $mode = \is_string($modeValue) ? strtolower($modeValue) : self::MODE_OFF;
        if (!\in_array($mode, [self::MODE_OFF, self::MODE_SHADOW, self::MODE_ENFORCE], true)) {
            $mode = self::MODE_OFF;
        }

        $values = [];
        $rawValues = $raw['config'] ?? null;
        if (\is_array($rawValues)) {
            foreach ($rawValues as $key => $value) {
                if (\is_string($key)) {
                    $values[$key] = $value;
                }
            }
        }

        $auto = $raw['auto'] ?? $values['auto'] ?? false;
        $values['auto'] = \is_bool($auto) ? $auto : filter_var($auto, FILTER_VALIDATE_BOOL) === true;

        $rawSite = $raw['site'] ?? $site;
        $resolvedSite = \is_string($rawSite) ? $rawSite : $site;

        $varDir = \dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'var';
        $slug = self::slug($resolvedSite);

        $values['storage'] ??= [
            'driver' => 'file',
            'path' => $varDir . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . $slug,
        ];

        $values['log'] ??= [
            'enabled' => true,
            'path' => $varDir . DIRECTORY_SEPARATOR . 'log' . DIRECTORY_SEPARATOR . $slug . '.jsonl',
            'pii' => false,
        ];

        $config = new Config($values);

        $formValue = $raw['form'] ?? 'default';
        $responseValue = $raw['response'] ?? 'auto';

        return new self(
            site: $resolvedSite,
            mode: $mode,
            match: self::stringList($raw['match'] ?? []),
            skip: self::stringList($raw['skip'] ?? []),
            formId: \is_string($formValue) ? $formValue : 'default',
            responseType: \is_string($responseValue) ? $responseValue : 'auto',
            checker: new SpamChecker($config),
            config: $config,
        );
    }

    public function site(): string
    {
        return $this->site;
    }

    public function mode(): string
    {
        return $this->mode;
    }

    public function formId(): string
    {
        return $this->formId;
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $fields
     */
    public function shouldHandle(array $server, array $fields): bool
    {
        if ($this->mode === self::MODE_OFF) {
            return false;
        }

        $requestMethod = $server['REQUEST_METHOD'] ?? 'GET';
        if (!\is_string($requestMethod) || strtoupper($requestMethod) !== 'POST') {
            return false;
        }

        if ($fields === []) {
            return false;
        }

        $contentLength = $server['CONTENT_LENGTH'] ?? null;
        $length = 0;
        if (\is_int($contentLength)) {
            $length = $contentLength;
        } elseif (\is_string($contentLength) && is_numeric($contentLength)) {
            $length = (int) $contentLength;
        }

        if ($length > 8 * 1024 * 1024) {
            return false;
        }

        $uriValue = $server['REQUEST_URI'] ?? '';
        $uri = \is_string($uriValue) ? $uriValue : '';

        foreach ($this->skip as $pattern) {
            if ($this->matches($pattern, $uri)) {
                return false;
            }
        }

        if ($this->match === []) {
            return true;
        }

        foreach ($this->match as $pattern) {
            if ($this->matches($pattern, $uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $fields
     */
    public function evaluate(array $server, array $fields): Verdict
    {
        return $this->checker->checkRequest(
            RequestData::fromGlobals($server, $fields, $this->formId),
        );
    }

    /**
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $fields
     */
    public function run(?array $server = null, ?array $fields = null): false
    {
        if ($server === null) {
            /** @var array<string, mixed> $server */
            $server = $_SERVER;
        }

        if ($fields === null) {
            /** @var array<string, mixed> $fields */
            $fields = $_POST;
        }

        if (!$this->shouldHandle($server, $fields)) {
            return false;
        }

        try {
            $verdict = $this->evaluate($server, $fields);
        } catch (Throwable $exception) {
            error_log('[spam-guard] evaluation failed: ' . $exception->getMessage());

            return false;
        }

        if ($this->mode === self::MODE_SHADOW || !$verdict->isSpam()) {
            return false;
        }

        $this->reject($verdict, $server);
    }

    /**
     * Answer a spam submission and terminate.
     *
     * @param array<string, mixed> $server
     */
    /**
     * Build the response for a spam submission without producing output.
     *
     * Kept separate from {@see reject()} so the response matrix (json/html/
     * silent, auto-detection, status codes) is unit-testable.
     *
     * @param  array<string, mixed>                                             $server
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    public function buildResponse(Verdict $verdict, array $server = []): array
    {
        $type = $this->responseType;

        if ($type === 'auto') {
            $acceptValue = $server['HTTP_ACCEPT'] ?? $_SERVER['HTTP_ACCEPT'] ?? '';
            $accept = \is_string($acceptValue) ? $acceptValue : '';

            $uriValue = $server['REQUEST_URI'] ?? $_SERVER['REQUEST_URI'] ?? '';
            $uri = \is_string($uriValue) ? $uriValue : '';
            $type = str_contains($accept, 'application/json') || preg_match('#/(api|ajax|json)(/|\.|$)#i', $uri) === 1
                ? 'json'
                : 'html';
        }

        $headers = ['X-Spam-Guard' => 'blocked', 'Cache-Control' => 'no-store'];

        if ($type === 'silent') {
            return ['status' => 200, 'headers' => $headers, 'body' => ''];
        }

        if ($type === 'json') {
            $body = json_encode([
                'ok' => false,
                'error' => 'spam_detected',
                'message' => 'Заявка отклонена антиспам-проверкой.',
            ], JSON_UNESCAPED_UNICODE);

            return [
                'status' => 400,
                'headers' => $headers + ['Content-Type' => 'application/json; charset=utf-8'],
                'body' => $body === false ? '{}' : $body,
            ];
        }

        return [
            'status' => 400,
            'headers' => $headers + ['Content-Type' => 'text/html; charset=utf-8'],
            'body' => '<!doctype html><meta charset="utf-8"><title>Заявка отклонена</title>'
                . '<p>Заявка отклонена антиспам-проверкой. Если это ошибка, напишите нам обычной почтой.</p>',
        ];
    }

    /**
     * Answer a spam submission and terminate.
     *
     * @param array<string, mixed> $server
     */
    public function reject(Verdict $verdict, array $server = []): never
    {
        $requestUri = $server['REQUEST_URI'] ?? $_SERVER['REQUEST_URI'] ?? '';
        if (!\is_string($requestUri)) {
            $requestUri = '';
        }

        $remoteAddress = $server['REMOTE_ADDR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';
        if (!\is_string($remoteAddress)) {
            $remoteAddress = '';
        }

        error_log(\sprintf(
            '[spam-guard] blocked %s %s from %s: score=%d %s',
            $this->site,
            $requestUri,
            $remoteAddress,
            $verdict->score,
            implode('; ', $verdict->reasons()),
        ));

        $response = $this->buildResponse($verdict, $server);

        if (!headers_sent()) {
            http_response_code($response['status']);
            foreach ($response['headers'] as $name => $value) {
                header($name . ': ' . $value);
            }
        }

        echo $response['body'];

        exit;
    }
    /**
     * @param array<string, mixed> $fields
     * @param array<string, mixed> $server
     */
    public static function evaluateFor(
        string $site,
        array $fields,
        array $server,
        ?string $formId = null,
        ?string $configDir = null,
    ): Verdict {
        $guard = self::boot($site, $configDir);

        if ($formId !== null) {
            $guard = $guard->withFormId($formId);
        }

        return $guard->evaluate($server, $fields);
    }

    private function withFormId(string $formId): self
    {
        return new self(
            $this->site,
            $this->mode,
            $this->match,
            $this->skip,
            $formId,
            $this->responseType,
            $this->checker,
            $this->config,
        );
    }

    private static function disabled(string $site): self
    {
        return new self(
            site: $site,
            mode: self::MODE_OFF,
            match: [],
            skip: [],
            formId: 'default',
            responseType: 'auto',
            checker: new SpamChecker(new Config()),
            config: new Config(),
        );
    }

    private static function detectSite(): string
    {
        $hostValue = $_SERVER['HTTP_HOST'] ?? '';
        $host = \is_string($hostValue) ? $hostValue : '';

        if ($host === '') {
            return 'default';
        }

        return strtolower(preg_replace('/:\d+$/', '', $host) ?? $host);
    }

    /**
     * The file may return anything; the caller validates the shape.
     */
    private static function loadConfigFile(string $file): mixed
    {
        $mtime = @filemtime($file);

        if ($mtime === false) {
            throw new RuntimeException('configuration file is not readable');
        }

        $cached = self::$cache[$file] ?? null;

        if (\is_array($cached) && $cached['mtime'] === $mtime) {
            return $cached['data'];
        }

        /** @psalm-suppress UnresolvableInclude */
        $data = require $file;

        if (\is_array($data)) {
            $typedData = [];
            foreach ($data as $key => $value) {
                if (\is_string($key)) {
                    $typedData[$key] = $value;
                }
            }

            self::$cache[$file] = ['mtime' => $mtime, 'data' => $typedData];
        }

        return $data;
    }

    private static function slug(string $site): string
    {
        $site = strtolower(trim($site));
        $site = preg_replace('#^www\.#', '', $site) ?? $site;

        $slugValue = preg_replace('/[^a-z0-9._-]+/', '_', $site);
        if ($slugValue === null || $slugValue === '') {
            return 'default';
        }

        return $slugValue;
    }

    /**
     * @param  mixed        $value
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!\is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $item) {
            if (\is_string($item) && $item !== '') {
                $result[] = $item;
            }
        }

        return $result;
    }

    private function matches(string $pattern, string $uri): bool
    {
        return @preg_match($pattern, $uri) === 1;
    }
}
