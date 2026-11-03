<?php

declare(strict_types=1);

namespace FormSpamChecker;

use FormSpamChecker\Cache\ArrayCache;
use FormSpamChecker\Cache\CacheInterface;
use FormSpamChecker\Cache\FileCache;
use FormSpamChecker\Cache\NullCache;
use FormSpamChecker\Check\BanCheck;
use FormSpamChecker\Check\EmailCheck;
use FormSpamChecker\Check\HoneypotCheck;
use FormSpamChecker\Check\KeywordCheck;
use FormSpamChecker\Check\LanguageCheck;
use FormSpamChecker\Check\LengthCheck;
use FormSpamChecker\Check\LinkCheck;
use FormSpamChecker\Check\RateLimitCheck;
use FormSpamChecker\Check\RepetitionCheck;
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Check\SqlInjectionCheck;
use FormSpamChecker\Check\TimeTrapCheck;
use FormSpamChecker\Check\UserAgentCheck;
use FormSpamChecker\Check\XssCheck;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Dns\CachedResolver;
use FormSpamChecker\Dns\DnsGetRecordResolver;
use FormSpamChecker\Dns\ResolverInterface;
use FormSpamChecker\Http\CurlClient;
use FormSpamChecker\Http\HttpClientInterface;
use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\Log\LoggerInterface;
use FormSpamChecker\Log\VerdictLogger;
use FormSpamChecker\Pipeline\SpamPipeline;
use FormSpamChecker\Security\AutoBan;
use FormSpamChecker\Security\Fail2Ban;
use FormSpamChecker\Storage\FileStorage;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Storage\StorageInterface;
use Throwable;

/**
 * Facade used by form integrations: builds the v2 pipeline from configuration
 * and returns a verdict for one submission.
 *
 *     $checker = new SpamChecker(Config::fromFile(__DIR__ . '/spam.php'));
 *     $verdict = $checker->check($_POST, Context::fromGlobals(), 'contact');
 *     if ($verdict->isSpam()) { http_response_code(400); exit; }
 *
 * The 1.x method `check(array $fields, ?Context, string $formId)` is kept as a
 * compatibility layer over {@see RequestData}; new code should pass a
 * RequestData to `checkRequest()`.
 */
final class SpamChecker
{
    /**
     * @param list<SpamCheckInterface>|null $checks explicit pipeline override (tests)
     */
    public function __construct(
        private readonly Config $config,
        private readonly ?StorageInterface $storage = null,
        private readonly ?array $checks = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly ?HttpClientInterface $http = null,
        private readonly ?CacheInterface $cache = null,
        private readonly ?ResolverInterface $dns = null,
    ) {}

    /**
     * @param list<SpamCheckInterface>|null $checks
     */
    public static function fromConfig(
        Config $config,
        ?StorageInterface $storage = null,
        ?array $checks = null,
        ?LoggerInterface $logger = null,
        ?HttpClientInterface $http = null,
        ?CacheInterface $cache = null,
        ?ResolverInterface $dns = null,
    ): self {
        return new self($config, $storage, $checks, $logger, $http, $cache, $dns);
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * 1.x-compatible entry point.
     *
     * @param array<string, mixed> $fields
     */
    public function check(array $fields, ?Context $context = null, string $formId = 'default'): Verdict
    {
        return $this->checkRequest($this->requestFromLegacy($fields, $context, $formId));
    }

    public function checkRequest(RequestData $request): Verdict
    {
        $config = $this->config->form($request->formId);
        $storage = $this->storage ?? self::createStorage($config);
        $logger = $this->logger ?? new ErrorLogLogger('pipeline');

        $checks = $this->checks ?? self::defaultChecks(
            $config,
            $storage,
            $logger,
            $this->http ?? new CurlClient(),
            $this->cache ?? self::createCache($config),
            $this->dns ?? self::createDns($config),
        );

        $verdict = (new SpamPipeline($checks))->process($request, $config);

        $this->applySecurityTools($config, $storage, $logger, $request, $verdict);

        $this->log($config, $verdict, $request);

        return $verdict;
    }

    /**
     * The standard pipeline: cheap local checks first, network checks last.
     *
     * @return list<SpamCheckInterface>
     */
    public static function defaultChecks(
        Config $config,
        StorageInterface $storage,
        ?LoggerInterface $logger = null,
        ?HttpClientInterface $http = null,
        ?CacheInterface $cache = null,
        ?ResolverInterface $dns = null,
    ): array {
        /** @var list<SpamCheckInterface> $checks */
        $checks = [
            new HoneypotCheck($config),
            new TimeTrapCheck($config),
            new UserAgentCheck($config),
            new RateLimitCheck($config, $storage),
            new LengthCheck($config),
            new SqlInjectionCheck($config),
            new XssCheck($config),
            new LinkCheck($config),
            new KeywordCheck($config),
            new EmailCheck($config),
            new RepetitionCheck($config),
            new LanguageCheck($config),
        ];

        if ($config->bool('autoban.enabled', false) && class_exists(BanCheck::class)) {
            $fail2ban = self::createFail2Ban($config, $logger);
            array_unshift($checks, new BanCheck(new AutoBan($config, $storage, $fail2ban)));
        }

        $logger ??= new ErrorLogLogger('pipeline');
        $http ??= new CurlClient();
        $cache ??= self::createCache($config);
        $dnsProvided = $dns !== null;
        $dns ??= self::createDns($config, $cache);

        // Behavioural additions (files may be absent during a partial deploy).
        if ($config->bool('behavioral.honeypot.dynamic', true)
            && $config->string('behavioral.honeypot.secret') !== ''
            && class_exists(Check\DynamicHoneypotCheck::class)
        ) {
            $checks[] = new Check\DynamicHoneypotCheck($config);
        }

        if ($config->bool('behavioral.js_challenge.enabled', false)
            && class_exists(Check\JsChallengeCheck::class)
        ) {
            $checks[] = new Check\JsChallengeCheck($config);
        }

        // Remote checks run last and only when configured.
        if ($config->bool('abuseipdb.enabled', false) && class_exists(Check\AbuseIpdbCheck::class)) {
            $checks[] = new Check\AbuseIpdbCheck($http, $cache, $logger, $config);
        }

        if ($config->bool('dnsbl.enabled', false) && class_exists(Check\DnsblCheck::class)) {
            // DNSBL has its own cache TTL; SPF/DMARC keep the shared resolver.
            $dnsblDns = $dnsProvided ? $dns : self::createDns($config, $cache, 'dnsbl.cache_ttl');
            $checks[] = new Check\DnsblCheck($dnsblDns, $config);
        }

        if ($config->bool('spf.enabled', false) && class_exists(Check\SpfCheck::class)) {
            $checks[] = new Check\SpfCheck($dns, $config);
        }

        if ($config->bool('dmarc.enabled', false) && class_exists(Check\DmarcCheck::class)) {
            $checks[] = new Check\DmarcCheck($dns, $config);
        }

        if ($config->bool('bayes.enabled', false)
            && class_exists(Check\BayesCheck::class)
            && class_exists(Bayes\Classifier::class)
        ) {
            $checks[] = new Check\BayesCheck(self::createBayesClassifier($config, $cache), $config);
        }

        return $checks;
    }

    /**
     * Build the Bayesian classifier from configuration (model stored in cache).
     */
    public static function createBayesClassifier(Config $config, ?CacheInterface $cache = null): Bayes\Classifier
    {
        $cache ??= self::createCache($config);

        return new Bayes\Classifier(
            new Bayes\CacheModelStorage($cache, 'bayes.model.' . sha1($config->bayesStoragePath())),
            max(0, $config->int('bayes.min_documents', 20)),
            $config->float('bayes.threshold', 0.92),
        );
    }

    public static function createStorage(Config $config): StorageInterface
    {
        return match ($config->string('storage.driver', 'file')) {
            'memory' => new MemoryStorage(),
            default => new FileStorage($config->storagePath()),
        };
    }

    public static function createCache(Config $config): CacheInterface
    {
        return match ($config->string('cache.driver', 'file')) {
            'memory', 'array' => new ArrayCache(),
            'none', 'null' => new NullCache(),
            default => new FileCache($config->cachePath()),
        };
    }

    public static function createDns(Config $config, ?CacheInterface $cache = null, string $ttlKey = 'spf.dns_ttl'): ResolverInterface
    {
        $cache ??= self::createCache($config);

        return new CachedResolver(
            new DnsGetRecordResolver(),
            $cache,
            max(60, $config->int($ttlKey, 3600)),
        );
    }

    /**
     * @param array<string, mixed> $fields
     */
    private function requestFromLegacy(array $fields, ?Context $context, string $formId): RequestData
    {
        $context ??= Context::fromGlobals();
        $headers = [];

        if ($context->userAgent !== '') {
            $headers['user-agent'] = $context->userAgent;
        }
        if ($context->referer !== '') {
            $headers['referer'] = $context->referer;
        }

        $now = $context->now;

        return new RequestData(
            fields: $fields,
            ip: $context->ip,
            headers: $headers,
            method: 'POST',
            uri: $context->page,
            now: $now,
            formId: $formId,
        );
    }

    private function log(Config $config, Verdict $verdict, RequestData $request): void
    {
        if (!$config->bool('log.enabled', false)) {
            return;
        }

        $path = $config->string('log.path');
        if ($path === '') {
            return;
        }

        try {
            (new VerdictLogger(
                $path,
                $config->bool('log.pii', false),
                $config->bool('log.sample_fields', true),
                $config->excludedFields(),
            ))->log($verdict, $request);
        } catch (Throwable) {
            // Logging must never break form processing.
        }
    }
    /**
     * Fail2Ban bridge for this configuration, or null when disabled.
     */
    public static function createFail2Ban(Config $config, ?LoggerInterface $logger = null): ?Fail2Ban
    {
        if (!$config->bool('fail2ban.enabled', false)) {
            return null;
        }

        return new Fail2Ban($config->fail2banLogPath(), $config->string('fail2ban.site'), $logger);
    }

    /**
     * Report a hard-spam verdict to Fail2Ban and the application auto-ban.
     *
     * Both layers are optional and fail-open: a reporting error must never
     * change the verdict or take a form down.
     */
    private function applySecurityTools(
        Config $config,
        StorageInterface $storage,
        LoggerInterface $logger,
        RequestData $request,
        Verdict $verdict,
    ): void {
        if (!$verdict->isSpam() || $request->ip === '') {
            return;
        }

        try {
            $fail2ban = self::createFail2Ban($config, $logger);
            $emitOn = $config->string('fail2ban.emit_on', 'both');

            if (
                $fail2ban !== null
                && ($emitOn === 'spam' || $emitOn === 'both')
                && $verdict->score >= $config->int('fail2ban.min_score', 60)
            ) {
                $fail2ban->report(
                    $request->ip,
                    'spam:' . implode(';', $verdict->reasons()),
                    $verdict->score,
                    $request->formId,
                );
            }

            if ($config->bool('autoban.enabled', false)) {
                (new AutoBan($config, $storage, $fail2ban))
                    ->recordAbuse($request->ip, 'spam', $verdict->score, $request->formId);
            }
        } catch (Throwable $exception) {
            error_log('[spam-checker] security reporting failed (fail open): ' . $exception->getMessage());
        }
    }
}
