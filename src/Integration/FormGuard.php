<?php

declare(strict_types=1);

namespace FormSpamChecker\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Verdict;

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
 * front controller is safe: static pages, GET requests and admin URLs simply
 * pass through.
 *
 * Modes:
 *  - off     — configuration is loaded but nothing runs;
 *  - shadow  — the verdict is computed and logged, the request always passes
 *              (use it for the first days of a new site);
 *  - enforce — spam is answered with a neutral error and the application never
 *              sees the request.
 *
 * The guard never throws into the application: configuration or storage
 * problems degrade to "off" and are written to the PHP error log.
 */
final class FormGuard
{
    public const string MODE_OFF = 'off';
    public const string MODE_SHADOW = 'shadow';
    public const string MODE_ENFORCE = 'enforce';

    /**
     * Loaded configurations, keyed by file path, with the mtime that was
     * current when the file was read. On a PHP-FPM worker this avoids re-reading
     * and re-parsing the config on every request while still picking up edits
     * without a restart.
     *
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
    ) {
    }

    /**
     * Load the guard for a site.
     *
     * @param string|null $site      host name; auto-detected from HTTP_HOST when null
     * @param string|null $configDir directory with <site>.php files
     */
    public static function boot(?string $site = null, ?string $configDir = null): self
    {
        $configDir ??= dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'sites';
        $site ??= self::detectSite();

        $file = $configDir . DIRECTORY_SEPARATOR . self::slug($site) . '.php';

        if (!is_file($file)) {
            $file = $configDir . DIRECTORY_SEPARATOR . 'default.php';
        }

        if (!is_file($file)) {
            return self::disabled($site);
        }

        try {
            /** @psalm-suppress UnresolvableInclude */
            $raw = self::loadConfigFile($file);
        } catch (\Throwable $exception) {
            error_log(sprintf('[spam-guard] cannot load config %s: %s', $file, $exception->getMessage()));

            return self::disabled($site);
        }

        if (!is_array($raw)) {
            error_log(sprintf('[spam-guard] config %s must return an array', $file));

            return self::disabled($site);
        }

        $mode = strtolower((string) ($raw['mode'] ?? self::MODE_OFF));
        if (!in_array($mode, [self::MODE_OFF, self::MODE_SHADOW, self::MODE_ENFORCE], true)) {
            $mode = self::MODE_OFF;
        }

        $values = is_array($raw['config'] ?? null) ? $raw['config'] : [];

        // Both forms are accepted for the auto-prepend switch: top-level
        // `'auto' => true` or `'config' => ['auto' => true]`.
        $values['auto'] = (bool) ($raw['auto'] ?? $values['auto'] ?? false);

        // Defaults for a shared installation: state and logs live in the module,
        // one sub-directory per site, so sites never write into their docroots.
        $varDir = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'var';
        $slug = self::slug((string) ($raw['site'] ?? $site));

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

        return new self(
            site: (string) ($raw['site'] ?? $site),
            mode: $mode,
            match: self::stringList($raw['match'] ?? []),
            skip: self::stringList($raw['skip'] ?? []),
            formId: (string) ($raw['form'] ?? 'default'),
            responseType: (string) ($raw['response'] ?? 'auto'),
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
     * Should this request be checked at all?
     *
     * @param array<string, mixed> $server
     */
    public function shouldHandle(array $server, array $fields): bool
    {
        if ($this->mode === self::MODE_OFF) {
            return false;
        }

        if (strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
            return false;
        }

        if ($fields === []) {
            return false;
        }

        // A body larger than the checker can meaningfully inspect is skipped:
        // file uploads belong to the application, not to a text heuristic.
        $length = isset($server['CONTENT_LENGTH']) ? (int) $server['CONTENT_LENGTH'] : 0;
        if ($length > 8 * 1024 * 1024) {
            return false;
        }

        $uri = (string) ($server['REQUEST_URI'] ?? '');

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
     * Evaluate the request without side effects on the response.
     *
     * @param array<string, mixed> $server
     * @param array<string, mixed> $fields
     */
    public function evaluate(array $server, array $fields): Verdict
    {
        return $this->checker->check($fields, Context::fromServer($server), $this->formId);
    }

    /**
     * Main entry point for the drop-in include. Returns true when the request
     * was rejected; in enforce mode a rejection terminates the script.
     *
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $fields
     */
    public function run(?array $server = null, ?array $fields = null): bool
    {
        $server ??= $_SERVER;
        $fields ??= $_POST;

        if (!$this->shouldHandle($server, $fields)) {
            return false;
        }

        try {
            $verdict = $this->evaluate($server, $fields);
        } catch (\Throwable $exception) {
            // A spam checker must never take a form down.
            error_log('[spam-guard] evaluation failed: ' . $exception->getMessage());

            return false;
        }

        if ($this->mode === self::MODE_SHADOW || !$verdict->isSpam()) {
            return false;
        }

        $this->reject($verdict, $server);

        return true;
    }

    /**
     * Answer a spam submission and terminate. Public so that an application
     * controller can reuse the guard's response format.
     *
     * @param array<string, mixed> $server
     */
    public function reject(Verdict $verdict, array $server = []): never
    {
        error_log(sprintf(
            '[spam-guard] blocked %s %s from %s: score=%d %s',
            $this->site,
            (string) ($server['REQUEST_URI'] ?? $_SERVER['REQUEST_URI'] ?? ''),
            (string) ($server['REMOTE_ADDR'] ?? $_SERVER['REMOTE_ADDR'] ?? ''),
            $verdict->score,
            implode('; ', $verdict->reasons()),
        ));

        if (!headers_sent()) {
            http_response_code(400);
            header('X-Spam-Guard: blocked');
            header('Cache-Control: no-store');
        }

        $type = $this->responseType;

        if ($type === 'auto') {
            $accept = (string) ($server['HTTP_ACCEPT'] ?? $_SERVER['HTTP_ACCEPT'] ?? '');
            $uri = (string) ($server['REQUEST_URI'] ?? $_SERVER['REQUEST_URI'] ?? '');
            $type = str_contains($accept, 'application/json') || preg_match('#/(api|ajax|json)(/|\.|$)#i', $uri) === 1
                ? 'json'
                : 'html';
        }

        if ($type === 'silent') {
            http_response_code(200);
            exit;
        }

        if ($type === 'json') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'ok' => false,
                'error' => 'spam_detected',
                'message' => 'Заявка отклонена антиспам-проверкой.',
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><meta charset="utf-8"><title>Заявка отклонена</title>'
            . '<p>Заявка отклонена антиспам-проверкой. Если это ошибка, напишите нам обычной почтой.</p>';
        exit;
    }

    /**
     * Convenience for controllers that build their own response: evaluate a
     * request against the shared configuration without terminating.
     *
     * @param array<string, mixed> $fields
     * @param array<string, mixed> $server
     */
    public static function evaluateFor(string $site, array $fields, array $server, ?string $formId = null, ?string $configDir = null): Verdict
    {
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
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');

        if ($host === '') {
            return 'default';
        }

        return strtolower(preg_replace('/:\d+$/', '', $host) ?? $host);
    }

    /**
     * Read a config file with a per-process cache keyed by path and mtime.
     *
     * @return array<string, mixed>
     */
    private static function loadConfigFile(string $file): mixed
    {
        $mtime = @filemtime($file);

        if ($mtime === false) {
            throw new \RuntimeException('configuration file is not readable');
        }

        $cached = self::$cache[$file] ?? null;

        if (is_array($cached) && $cached['mtime'] === $mtime) {
            return $cached['data'];
        }

        /** @psalm-suppress UnresolvableInclude */
        $data = require $file;

        if (is_array($data)) {
            self::$cache[$file] = ['mtime' => $mtime, 'data' => $data];
        }

        return $data;
    }

    private static function slug(string $site): string
    {
        $site = strtolower(trim($site));
        $site = preg_replace('#^www\.#', '', $site) ?? $site;

        return preg_replace('/[^a-z0-9._-]+/', '_', $site) ?: 'default';
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $item) {
            if (is_string($item) && $item !== '') {
                $result[] = $item;
            }
        }

        return $result;
    }

    private function matches(string $pattern, string $uri): bool
    {
        $result = @preg_match($pattern, $uri);

        return $result === 1;
    }
}
