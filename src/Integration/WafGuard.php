<?php

declare(strict_types=1);

namespace FormSpamChecker\Integration;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\Log\LoggerInterface;
use FormSpamChecker\Storage\FileStorage;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Storage\StorageInterface;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafRequest;
use FormSpamChecker\Waf\WafVerdict;

/**
 * Drop-in HTTP firewall for existing PHP sites, loaded from the shared module
 * directory (/var/www/lib/PHP-Form-Spam-Checker).
 *
 * A site adds one line before its front controller:
 *
 *     require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
 *
 * and a per-site configuration file `config/sites/<host>.php` — the same file
 * the form guard reads. The WAF reads its section from `config.waf`; two
 * top-level overrides keep day-to-day operation simple:
 *
 *     'waf_mode' => 'monitor',   // off | monitor | block
 *     'waf_skip' => ['#^/protected#'],  // replaces the default skip list
 *     'waf_match' => ['#^/api/#'],      // optional: only these URIs
 *     'waf_response' => 'auto',         // auto | json | html | silent
 *
 * Modes:
 *  - off     — configuration is loaded, nothing is inspected;
 *  - monitor — the verdict is computed and logged, the request always passes;
 *  - block   — a blocked request is answered and the script terminates.
 *
 * The default skip list protects the administrative areas where a false
 * positive would lock an operator out. The guard never throws into the
 * application: configuration, storage or rule problems degrade to "pass".
 */
final class WafGuard
{
    public const string MODE_OFF = 'off';
    public const string MODE_MONITOR = 'monitor';
    public const string MODE_BLOCK = 'block';

    /**
     * Administrative areas that must never be blocked by the drop-in.
     *
     * @var list<string>
     */
    private const array DEFAULT_SKIP = [
        '#^/bitrix/admin#i',
        '#^/wp-admin#i',
        '#^/admin(?:/|$)#i',
        '#^/login(?:/|$)#i',
        '#^/auth(?:/|$)#i',
        '#^/cpanel(?:/|$)#i',
    ];

    /**
     * Loaded configurations keyed by file path with the mtime they were read
     * at: on a PHP-FPM worker the file is parsed once and a changed file is
     * picked up without a restart.
     *
     * @var array<string, array{mtime: int, data: mixed}>
     */
    private static array $cache = [];

    /**
     * @param list<string> $match
     * @param list<string> $skip
     */
    private function __construct(
        private readonly string $site,
        private readonly string $mode,
        private readonly array $match,
        private readonly array $skip,
        private readonly string $responseType,
        private readonly int $blockStatus,
        private readonly Waf $waf,
        private readonly Config $config,
        private readonly bool $enabled,
    ) {
    }

    /**
     * Load the firewall for a site.
     *
     * @param string|null $site           host name; auto-detected from HTTP_HOST when null
     * @param string|null $configDir      directory with <site>.php files
     * @param SpamCheckInterface|null $ipReputation optional network collaborator
     * @param StorageInterface|null   $rateLimitStorage optional counter storage
     */
    public static function boot(
        ?string $site = null,
        ?string $configDir = null,
        ?SpamCheckInterface $ipReputation = null,
        ?StorageInterface $rateLimitStorage = null,
    ): self {
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
            $raw = self::loadConfigFile($file);
        } catch (\Throwable $exception) {
            error_log(sprintf('[waf] cannot load config %s: %s', $file, $exception->getMessage()));

            return self::disabled($site);
        }

        if (!is_array($raw)) {
            error_log(sprintf('[waf] config %s must return an array', $file));

            return self::disabled($site);
        }

        $values = is_array($raw['config'] ?? null) ? $raw['config'] : [];
        $config = new Config($values);

        $mode = strtolower((string) ($raw['waf_mode'] ?? $config->string('waf.mode', self::MODE_MONITOR)));
        if (!in_array($mode, [self::MODE_OFF, self::MODE_MONITOR, self::MODE_BLOCK], true)) {
            $mode = self::MODE_OFF;
        }

        $responseType = strtolower((string) ($raw['waf_response'] ?? $config->string('waf.response', 'auto')));
        if (!in_array($responseType, ['auto', 'json', 'html', 'silent'], true)) {
            $responseType = 'auto';
        }

        $blockStatus = $config->int('waf.block_status', 403);
        if ($blockStatus < 100 || $blockStatus > 599) {
            $blockStatus = 403;
        }

        $skip = self::stringList($raw['waf_skip'] ?? []);
        if ($skip === []) {
            $skip = self::DEFAULT_SKIP;
        }

        $enabled = $config->bool('waf.enabled', false);

        if ($rateLimitStorage === null && $enabled && self::ruleEnabled($config, 'rate_limit')) {
            $rateLimitStorage = self::counterStorage($config);
        }

        $logger = new ErrorLogLogger('waf');

        try {
            $waf = Waf::withDefaultRules($config, $ipReputation, $rateLimitStorage, $logger);
        } catch (\Throwable $exception) {
            error_log('[waf] cannot build the rule set, failing open: ' . $exception->getMessage());

            return self::disabled($site);
        }

        return new self(
            site: (string) ($raw['site'] ?? $site),
            mode: $mode,
            match: self::stringList($raw['waf_match'] ?? []),
            skip: $skip,
            responseType: $responseType,
            blockStatus: $blockStatus,
            waf: $waf,
            config: $config,
            enabled: $enabled,
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

    public function enabled(): bool
    {
        return $this->enabled;
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function waf(): Waf
    {
        return $this->waf;
    }

    /**
     * @return list<string>
     */
    public function skip(): array
    {
        return $this->skip;
    }

    public function responseType(): string
    {
        return $this->responseType;
    }

    /**
     * Should this request be inspected at all?
     */
    public function shouldInspect(WafRequest $request): bool
    {
        if (!$this->enabled || $this->mode === self::MODE_OFF) {
            return false;
        }

        foreach ($this->skip as $pattern) {
            if ($this->matches($pattern, $request->uri) || $this->matches($pattern, $request->path())) {
                return false;
            }
        }

        if ($this->match === []) {
            return true;
        }

        foreach ($this->match as $pattern) {
            if ($this->matches($pattern, $request->uri) || $this->matches($pattern, $request->path())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Evaluate one request without producing a response.
     */
    public function inspect(WafRequest $request): WafVerdict
    {
        return $this->waf->inspect($request);
    }

    /**
     * Main entry point for the drop-in include.
     *
     * Returns true when the request was answered as blocked; in block mode a
     * blocked request terminates the script. In monitor mode this method only
     * logs and always returns false.
     *
     * @param array<string, mixed>|null $server
     * @param array<string, mixed>|null $get
     * @param array<string, mixed>|null $post
     * @param array<string, mixed>|null $cookie
     */
    public function run(
        ?array $server = null,
        ?array $get = null,
        ?array $post = null,
        ?array $cookie = null,
        ?string $body = null,
    ): bool {
        try {
            $server ??= $_SERVER;

            $request = WafRequest::fromGlobals(
                $server,
                $get,
                $post,
                $cookie,
                $body,
                $this->maxBodyBytes(),
            );

            if (!$this->shouldInspect($request)) {
                return false;
            }

            $verdict = $this->waf->inspect($request);
        } catch (\Throwable $exception) {
            // A firewall must never take a site down.
            error_log('[waf] evaluation failed, failing open: ' . $exception->getMessage());

            return false;
        }

        $this->logVerdict($request, $verdict);

        if ($this->mode !== self::MODE_BLOCK || !$verdict->blocked) {
            return false;
        }

        $this->reject($request, $verdict);

        return true;
    }

    /**
     * Answer a blocked request and terminate. Public so that a front
     * controller can reuse the guard's response format.
     */
    public function reject(WafRequest $request, WafVerdict $verdict): never
    {
        error_log(sprintf(
            '[waf] blocked %s %s %s from %s: mode=block score=%d reasons=%s',
            $this->site,
            $request->method,
            $request->uri,
            $request->ip,
            $verdict->score,
            implode('; ', $verdict->reasons()),
        ));

        if (!headers_sent()) {
            http_response_code($this->blockStatus);
            header('X-WAF: blocked');
            header('Cache-Control: no-store');
        }

        $type = $this->responseType;

        if ($type === 'auto') {
            $accept = $request->header('accept');
            $type = str_contains($accept, 'application/json')
                || preg_match('#/(api|ajax|json)(/|\.|$)#i', $request->uri) === 1
                ? 'json'
                : 'html';
        }

        if ($type === 'silent') {
            if (!headers_sent()) {
                http_response_code(200);
            }

            exit;
        }

        if ($type === 'json') {
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
            }

            echo json_encode([
                'ok' => false,
                'error' => 'waf_blocked',
                'message' => 'Запрос отклонён защитой сайта.',
            ], JSON_UNESCAPED_UNICODE);

            exit;
        }

        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }

        echo '<!doctype html><meta charset="utf-8"><title>Запрос отклонён</title>'
            . '<p>Запрос отклонён защитой сайта.</p>';

        exit;
    }

    private function logVerdict(WafRequest $request, WafVerdict $verdict): void
    {
        if ($verdict->findings === []) {
            return;
        }

        error_log(sprintf(
            '[waf] verdict %s %s %s from %s: mode=%s status=%s score=%d reasons=%s',
            $this->site,
            $request->method,
            $request->uri,
            $request->ip,
            $this->mode,
            $verdict->status,
            $verdict->score,
            implode('; ', $verdict->reasons()),
        ));
    }

    private function maxBodyBytes(): int
    {
        return max(0, $this->config->int('waf.max_body_bytes', WafRequest::DEFAULT_MAX_BODY_BYTES));
    }

    private static function disabled(string $site): self
    {
        $config = new Config();
        $logger = new ErrorLogLogger('waf');

        return new self(
            site: $site,
            mode: self::MODE_OFF,
            match: [],
            skip: [],
            responseType: 'auto',
            blockStatus: 403,
            waf: new Waf($config, [], $logger),
            config: $config,
            enabled: false,
        );
    }

    /**
     * Build the storage the rate-limit rule uses.
     *
     * The directory lives next to the form-checker state (`storage.path`), so a
     * shared installation never writes into a site's document root.
     */
    private static function counterStorage(Config $config): ?StorageInterface
    {
        $driver = strtolower($config->string('storage.driver', 'file'));

        try {
            return match ($driver) {
                'memory' => new MemoryStorage(),
                'file' => new FileStorage(rtrim($config->storagePath(), '/\\') . DIRECTORY_SEPARATOR . 'waf'),
                default => null,
            };
        } catch (\Throwable $exception) {
            error_log('[waf] rate-limit storage unavailable, rule disabled: ' . $exception->getMessage());

            return null;
        }
    }

    private static function ruleEnabled(Config $config, string $rule): bool
    {
        $raw = $config->get('waf.rules.' . $rule, false);

        if (is_bool($raw)) {
            return $raw;
        }

        if (is_array($raw)) {
            if (!array_key_exists('enabled', $raw)) {
                return false;
            }

            return filter_var($raw['enabled'], FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? false;
        }

        return false;
    }

    private static function detectSite(): string
    {
        $host = (string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '');

        if ($host === '') {
            return 'default';
        }

        return strtolower(preg_replace('/:\d+$/', '', $host) ?? $host);
    }

    /**
     * Read a config file with a per-process cache keyed by path and mtime.
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

        self::$cache[$file] = ['mtime' => $mtime, 'data' => $data];

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
        return @preg_match($pattern, $uri) === 1;
    }
}
