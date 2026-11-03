<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Cache\ArrayCache;
use FormSpamChecker\Cache\NullCache;
use FormSpamChecker\Check\KeywordCheck;
use FormSpamChecker\Check\LinkCheck;
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Check\TimeTrapCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Dns\CachedResolver;
use FormSpamChecker\Dns\ResolverInterface;
use FormSpamChecker\FormProtector;
use FormSpamChecker\Http\CheckEndpoint;
use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\Pipeline\SpamPipeline;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Status;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Support\SpfEvaluation;
use FormSpamChecker\Support\SpfResult;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Token\FormToken;
use InvalidArgumentException;
use RuntimeException;

/**
 * Branch-coverage tests for small support classes and edge paths.
 */
final class MiscCoverageTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0';

    private function request(array $fields, array $headers = [], ?int $now = null): RequestData
    {
        return new RequestData($fields, '203.0.113.10', $headers, [], [], 'POST', '/form', '', $now ?? 1_700_000_000, 'contact');
    }

    public function testStatusHelpers(): void
    {
        self::assertSame('clean', Status::Clean->label());
        self::assertSame('suspicious', Status::Suspicious->label());
        self::assertSame('spam', Status::Spam->label());
        self::assertTrue(Status::Spam->isFlagged());
        self::assertFalse(Status::Clean->isFlagged());
        self::assertTrue(Status::Clean->isClean());
        self::assertFalse(Status::Spam->isClean());
    }

    public function testNullCache(): void
    {
        $cache = new NullCache();
        $cache->set('k', 'v', 10);

        self::assertNull($cache->get('k'));
        self::assertFalse($cache->has('k'));
        $cache->delete('k');
    }

    public function testErrorLogLoggerWritesAllLevels(): void
    {
        $log = $this->tempDir() . '/error.log';
        $previous = ini_set('error_log', $log);

        try {
            $logger = new ErrorLogLogger('test');
            $logger->error('err {x}', ['x' => '1']);
            $logger->warning('warn');
            $logger->info('info');
            $logger->debug('debug');
            $logger->log('notice', 'notice');
        } finally {
            ini_set('error_log', $previous === false ? '' : $previous);
        }

        $content = (string) file_get_contents($log);
        self::assertStringContainsString('ERROR: err 1', $content);
        self::assertStringContainsString('WARNING: warn', $content);
        self::assertStringContainsString('INFO: info', $content);
        self::assertStringContainsString('DEBUG: debug', $content);
        self::assertStringContainsString('NOTICE: notice', $content);
    }

    public function testCachedResolverCachesAndDelegates(): void
    {
        $inner = new class implements ResolverInterface {
            public int $calls = 0;

            /** @return list<string> */
            public function txt(string $name): array
            {
                $this->calls++;

                return ['v=spf1 -all'];
            }

            /** @return list<string> */
            public function a(string $name): array
            {
                return ['127.0.0.2'];
            }

            /** @return list<string> */
            public function mx(string $name): array
            {
                return ['mx.example.ru'];
            }
        };

        $resolver = new CachedResolver($inner, new ArrayCache(), 60);

        self::assertSame(['v=spf1 -all'], $resolver->txt('example.ru'));
        self::assertSame(['v=spf1 -all'], $resolver->txt('example.ru'));
        self::assertSame(1, $inner->calls);
        self::assertSame(['127.0.0.2'], $resolver->a('example.ru'));
        self::assertSame(['mx.example.ru'], $resolver->mx('example.ru'));
    }

    public function testContextFromGlobalsAndAliases(): void
    {
        $previous = $_SERVER;
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5, 127.0.0.1',
            'HTTP_USER_AGENT' => 'UA/1',
            'HTTP_REFERER' => 'https://ref',
            'REQUEST_URI' => '/p',
        ];

        try {
            $context = Context::fromGlobals();
        } finally {
            $_SERVER = $previous;
        }

        self::assertSame('203.0.113.5', $context->ip);
        self::assertSame('UA/1', $context->userAgent);
        self::assertSame('https://ref', $context->referer);
        self::assertSame('/p', $context->page);
        self::assertSame('UA/1', $context->toArray()['userAgent']);

        $cloudflare = Context::fromArray(['ip' => '203.0.113.6', 'ua' => 'UA/2', 'now' => 1700000000]);
        self::assertSame('UA/2', $cloudflare->userAgent);
        self::assertSame(1700000000, $cloudflare->timestamp());
        self::assertSame(1700000000, $cloudflare->toArray()['now']);
    }

    public function testTimeTrapBranches(): void
    {
        $secret = '0123456789abcdef-secret';
        $now = 1_700_000_000;

        $future = (new FormToken($secret))->issue('contact', $now + 60);
        $config = new Config(['time_trap' => ['enabled' => true, 'secret' => $secret]]);
        self::assertSame(CheckStatus::SPAM, (new TimeTrapCheck($config))->check($this->request(['_fs_ts' => $future], [], $now))->status);

        $optional = new Config(['time_trap' => ['enabled' => true, 'secret' => $secret, 'require_token' => false]]);
        self::assertSame(CheckStatus::HAM, (new TimeTrapCheck($optional))->check($this->request([], [], $now))->status);

        $misconfigured = new Config(['time_trap' => ['enabled' => true, 'secret' => 'short']]);
        self::assertSame(CheckStatus::ERROR, (new TimeTrapCheck($misconfigured))->check($this->request(['_fs_ts' => 'x.y'], [], $now))->status);
    }

    public function testKeywordBranches(): void
    {
        $config = new Config(['keywords' => ['scan_fields' => ['message'], 'patterns' => ['/bad/'], 'per_hit' => 5]]);
        $check = new KeywordCheck($config);

        self::assertGreaterThan(0, $check->check($this->request(['message' => 'bad', 'name' => 'casino']))->score);
        self::assertSame(0, $check->check($this->request(['name' => 'casino', 'message' => 'ok']))->score);
        self::assertSame(CheckStatus::HAM, (new KeywordCheck(new Config(['keywords' => ['enabled' => false]])))->check($this->request(['message' => 'casino']))->status);
    }

    public function testLinkBranches(): void
    {
        $check = new LinkCheck(new Config(['links' => ['enabled' => false]]));
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'https://a.ru']))->status);

        $shortener = new LinkCheck(new Config());
        self::assertGreaterThan(0, $shortener->check($this->request(['message' => 'https://bit.ly/x']))->score);
        self::assertSame(0, $shortener->check($this->request(['message' => 'обычный текст']))->score);
    }

    public function testFormProtectorRendersJsChallenge(): void
    {
        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'behavioral' => ['js_challenge' => ['enabled' => true, 'secret' => '0123456789abcdef-secret']],
        ]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $html = $protector->fields('contact');

        self::assertStringContainsString('data-fs-js="1"', $html);
        self::assertStringContainsString('_js_token', $html);
        self::assertStringContainsString('<script>', $html);
    }

    public function testSpamPipelineStopsAndFailsOpen(): void
    {
        $spam = new class implements SpamCheckInterface {
            public function name(): string
            {
                return 'first';
            }

            public function check(RequestData $data): CheckOutcome
            {
                return CheckOutcome::spam('first', 'hard');
            }
        };
        $second = new class implements SpamCheckInterface {
            public function name(): string
            {
                return 'second';
            }

            public function check(RequestData $data): CheckOutcome
            {
                return CheckOutcome::ham('second');
            }
        };

        $config = new Config(['pipeline' => ['stop_on_spam' => true]]);
        $verdict = (new SpamPipeline([$spam, $second]))->process($this->request([]), $config);
        self::assertSame(['first'], array_map(static fn($o): string => $o->check, $verdict->outcomes));

        $all = (new SpamPipeline([$spam, $second]))->process($this->request([]), new Config(['pipeline' => ['stop_on_spam' => false]]));
        self::assertCount(2, $all->outcomes);

        $throwing = new class implements SpamCheckInterface {
            public function name(): string
            {
                return 'boom';
            }

            public function check(RequestData $data): CheckOutcome
            {
                throw new RuntimeException('boom');
            }
        };
        $failOpen = (new SpamPipeline([$throwing]))->process($this->request([]), new Config());
        self::assertSame(CheckStatus::ERROR, $failOpen->outcomes[0]->status);
        self::assertTrue($failOpen->isClean());
    }

    public function testRequestDataFromGlobalsExtras(): void
    {
        $previous = $_SERVER;
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.7',
            'HTTP_CF_CONNECTING_IP' => '203.0.113.8',
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '2',
            'REQUEST_METHOD' => 'post',
            'REQUEST_URI' => '/api',
            'QUERY_STRING' => 'a=1',
        ];

        try {
            $request = RequestData::fromGlobals($_SERVER, ['name' => 'Иван'], 'lead');
        } finally {
            $_SERVER = $previous;
        }

        self::assertSame('203.0.113.8', $request->ip);
        self::assertSame('application/json', $request->header('content-type'));
        self::assertSame(['a' => '1'], $request->query);
        self::assertSame('POST', $request->method);
        self::assertSame('lead', $request->formId);
        self::assertSame('Иван', $request->sample()['name']);
        self::assertIsArray($request->toArray());
    }

    public function testVerdictFromArrayRejectsUnknownStatus(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Verdict::fromArray(['status' => 'nope', 'score' => 0, 'checks' => []]);
    }

    public function testSpfEvaluationHelpers(): void
    {
        $evaluation = new SpfEvaluation('example.ru', SpfResult::PASS, 'ok', 1, 'v=spf1 -all');
        self::assertTrue($evaluation->isPass());
        self::assertFalse($evaluation->isFail());
        self::assertFalse($evaluation->isSoftFail());
        self::assertFalse($evaluation->isNeutral());
        self::assertFalse($evaluation->isNone());
        self::assertFalse($evaluation->isPermError());
        self::assertFalse($evaluation->isTempError());
    }

    public function testEndpointRespondMatrix(): void
    {
        $endpoint = new CheckEndpoint(new Config([
            'storage' => ['driver' => 'memory'],
            'endpoint' => ['key' => 'secret', 'max_body_bytes' => 2048],
        ]));

        self::assertSame(405, $endpoint->respond('GET', [], '')['status']);
        self::assertSame(403, $endpoint->respond('POST', [], '{}')['status']);
        self::assertSame(403, $endpoint->respond('POST', ['HTTP_X_SPAM_CHECKER_KEY' => 'wrong'], '{}')['status']);
        self::assertSame(400, $endpoint->respond('POST', ['HTTP_X_SPAM_CHECKER_KEY' => 'secret'], '')['status']);
        self::assertSame(400, $endpoint->respond('POST', ['HTTP_X_SPAM_CHECKER_KEY' => 'secret'], '{broken')['status']);
        self::assertSame(413, $endpoint->respond('POST', ['HTTP_X_SPAM_CHECKER_KEY' => 'secret'], str_repeat('x', 4096))['status']);

        $ok = $endpoint->respond(
            'POST',
            ['HTTP_X_SPAM_CHECKER_KEY' => 'secret'],
            (string) json_encode(['name' => 'Иван', 'context' => ['ip' => '203.0.113.1', 'userAgent' => self::UA]]),
        );
        self::assertSame(200, $ok['status']);
        self::assertStringContainsString('"status":"clean"', $ok['body']);
    }
}
