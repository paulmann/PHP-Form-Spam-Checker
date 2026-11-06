<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Bayes\CacheModelStorage;
use FormSpamChecker\Bayes\Classifier;
use FormSpamChecker\Cache\ArrayCache;
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\FormProtector;
use FormSpamChecker\Http\CheckEndpoint;
use FormSpamChecker\Integration\FormGuard;
use FormSpamChecker\Integration\WafGuard;
use FormSpamChecker\Log\NullLogger;
use FormSpamChecker\Pipeline\SpamPipeline;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Status;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafRequest;

/**
 * Method-level coverage for small public surfaces added with the
 * rejected-forms registry and a few library entry points the integration
 * tests exercise only through subprocesses (which coverage cannot see).
 */
final class ExtraCoverageV22Test extends TempDirTestCase
{
    public function testNullLoggerAcceptsEveryLevel(): void
    {
        $logger = new NullLogger();
        $logger->log('debug', 'message', ['context' => true]);
        $logger->debug('message');
        $logger->info('message');
        $logger->warning('message');
        $logger->error('message');

        self::assertTrue(true);
    }

    public function testArrayCacheHasAndDelete(): void
    {
        $cache = new ArrayCache();

        self::assertFalse($cache->has('key'));
        $cache->set('key', 'value', 60);
        self::assertTrue($cache->has('key'));
        $cache->delete('key');
        self::assertFalse($cache->has('key'));
    }

    public function testConfigFromArray(): void
    {
        $config = Config::fromArray(['thresholds' => ['spam' => 50]]);

        self::assertSame(50, $config->int('thresholds.spam'));
    }

    public function testStatusIsSpam(): void
    {
        self::assertTrue(Status::Spam->isSpam());
        self::assertFalse(Status::Clean->isSpam());
        self::assertFalse(Status::Suspicious->isSpam());
    }

    public function testPipelineAddReturnsNewPipeline(): void
    {
        $check = new class implements SpamCheckInterface {
            public function name(): string
            {
                return 'extra';
            }

            public function check(RequestData $data): CheckOutcome
            {
                return CheckOutcome::ham('extra');
            }
        };

        $pipeline = (new SpamPipeline([]))->add($check);
        $verdict = $pipeline->process(
            new RequestData(['name' => 'Иван'], '203.0.113.5', [], [], [], 'POST', '/', '', 1_700_000_000, 'contact'),
            new Config(),
        );

        self::assertSame(['extra'], array_map(static fn($o): string => $o->check, $verdict->outcomes));
    }

    public function testSpamCheckerFromConfig(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory']]);
        $checker = SpamChecker::fromConfig($config);

        self::assertSame($config, $checker->config());
    }

    public function testFormProtectorExposesConfig(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory']]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        self::assertSame($config, $protector->config());
    }

    public function testWafExposesConfig(): void
    {
        $config = new Config();
        $waf = new Waf($config, [], new NullLogger());

        self::assertSame($config, $waf->config());
    }

    public function testClassifierSaveAliasPersists(): void
    {
        $storage = new CacheModelStorage(new ArrayCache());
        $classifier = new Classifier($storage, 0, 0.5);
        $classifier->train('hello world', true);
        $classifier->save();

        $fresh = new Classifier($storage, 0, 0.5);
        $fresh->load();

        self::assertSame(1, $fresh->documentCount());
    }

    public function testRejectedStoreExposesSite(): void
    {
        $store = new \FormSpamChecker\Integration\RejectedStore(
            new Config(['rejected' => ['path' => $this->tempDir() . '/registry']]),
            'example.ru',
        );

        self::assertSame('example.ru', $store->site());
        self::assertTrue($store->enabled());
    }

    public function testEndpointFromEnvironment(): void
    {
        $config = $this->tempDir() . '/endpoint.json';
        file_put_contents($config, '{"endpoint":{"key":"k"},"storage":{"driver":"memory"}}');

        $previous = getenv('SPAM_CHECKER_CONFIG');
        putenv('SPAM_CHECKER_CONFIG=' . $config);

        try {
            $endpoint = CheckEndpoint::fromEnvironment();
        } finally {
            putenv($previous === false ? 'SPAM_CHECKER_CONFIG' : 'SPAM_CHECKER_CONFIG=' . $previous);
        }

        self::assertInstanceOf(CheckEndpoint::class, $endpoint);
        self::assertTrue($endpoint->isAuthorized('k'));
    }

    public function testFormGuardCaptureRejectedWritesRecord(): void
    {
        $dir = $this->tempDir();
        $registry = $dir . '/registry';
        $site = $dir . '/extra.example.php';

        file_put_contents($site, '<?php return ' . var_export([
            'site' => 'extra.example',
            'mode' => 'enforce',
            'form' => 'contact',
            'match' => [],
            'skip' => [],
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
                'rejected' => ['enabled' => true, 'path' => $registry],
                'language' => [
                    'enabled' => true,
                    'require_cyrillic' => true,
                    'missing_score' => 60,
                    'max_score' => 100,
                ],
            ],
        ], true) . ';');

        $guard = FormGuard::boot('extra.example', $dir);
        $server = [
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/contact',
            'HTTP_HOST' => 'extra.example',
            'REMOTE_ADDR' => '203.0.113.5',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/140',
        ];
        $fields = ['name' => 'John Smith', 'email' => 'john@example.com'];

        $verdict = $guard->evaluate($server, $fields);
        self::assertTrue($verdict->isSpam());

        $record = $guard->captureRejected($verdict, $server, $fields);

        self::assertIsArray($record);
        self::assertSame('extra.example', $record['site']);
        self::assertFileExists($registry . '/' . $record['id'] . '.json');
    }

    public function testWafGuardCaptureRejectedWritesRecord(): void
    {
        $dir = $this->tempDir();
        $registry = $dir . '/waf-registry';
        $site = $dir . '/waf.example.php';

        file_put_contents($site, '<?php return ' . var_export([
            'site' => 'waf.example',
            'mode' => 'enforce',
            'form' => 'contact',
            'match' => [],
            'skip' => [],
            'config' => [
                'storage' => ['driver' => 'memory'],
                'log' => ['enabled' => false],
                'waf' => ['enabled' => true, 'mode' => 'block'],
                'rejected' => ['enabled' => true, 'path' => $registry],
            ],
        ], true) . ';');

        $guard = WafGuard::boot('waf.example', $dir);
        $request = new WafRequest(
            method: 'GET',
            uri: '/?q=1%20UNION%20SELECT%20x%20FROM%20y',
            ip: '203.0.113.6',
            query: ['q' => '1 UNION SELECT x FROM y'],
            headers: ['host' => 'waf.example', 'user-agent' => 'Mozilla/5.0 Chrome/140'],
            formId: 'contact',
        );

        $verdict = $guard->inspect($request);
        self::assertTrue($verdict->isBlocked());

        $previousServer = $_SERVER;
        $_SERVER = [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_HOST' => 'waf.example',
            'REMOTE_ADDR' => '203.0.113.6',
        ];

        try {
            $record = $guard->captureRejected($request, $verdict);
        } finally {
            $_SERVER = $previousServer;
        }

        self::assertIsArray($record);
        self::assertSame('waf', $record['reason']);
        self::assertFileExists($registry . '/' . $record['id'] . '.json');
    }

    public function testWafGuardBootDetectsHostFromServer(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/detected.example.php', '<?php return ' . var_export([
            'site' => 'detected.example',
            'mode' => 'enforce',
            'form' => 'contact',
            'match' => [],
            'skip' => [],
            'config' => ['storage' => ['driver' => 'memory'], 'waf' => ['enabled' => true, 'mode' => 'monitor']],
        ], true) . ';');

        $previous = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'detected.example';

        try {
            $guard = WafGuard::boot(null, $dir);
        } finally {
            $_SERVER = $previous;
        }

        self::assertSame('detected.example', $guard->site());
        self::assertTrue($guard->enabled());
    }

    public function testWafRateLimitRuleBuildsCounterStorage(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/ratelimit.example.php', '<?php return ' . var_export([
            'site' => 'ratelimit.example',
            'mode' => 'enforce',
            'form' => 'contact',
            'match' => [],
            'skip' => [],
            'config' => [
                'storage' => ['driver' => 'memory'],
                'waf' => ['enabled' => true, 'mode' => 'block', 'rules' => ['rate_limit' => true]],
            ],
        ], true) . ';');

        $guard = WafGuard::boot('ratelimit.example', $dir);
        $request = new WafRequest('GET', '/page', '203.0.113.9', headers: ['host' => 'ratelimit.example']);

        $verdict = $guard->inspect($request);

        self::assertFalse($verdict->isBlocked());
    }

    public function testRequestDataTrustsForwardedForFromLoopback(): void
    {
        $request = RequestData::fromGlobals([
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.44, 127.0.0.1',
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/',
        ], ['name' => 'Иван'], 'contact');

        self::assertSame('203.0.113.44', $request->ip);
    }
}
