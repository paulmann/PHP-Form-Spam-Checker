<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Status;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class SpamCheckerV2Test extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private function config(array $extra = []): Config
    {
        return new Config([
            'storage' => ['driver' => 'memory'],
            'cache' => ['driver' => 'memory'],
            'log' => ['enabled' => false],
            ...$extra,
        ]);
    }

    private function request(array $fields, string $formId = 'contact'): RequestData
    {
        return new RequestData($fields, '203.0.113.10', ['user-agent' => self::UA], [], [], 'POST', '/form', '', 1_700_000_000, $formId);
    }

    public function testCleanSubmissionPassesDefaultPipeline(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        $verdict = $checker->checkRequest($this->request([
            'name' => 'Иван Петров',
            'company' => 'ООО Энергосервис',
            'email' => 'ivan@example.ru',
            'phone' => '+7 999 000-00-00',
            'message' => 'Нужен отчёт по протоколу испытаний за октябрь.',
        ]));

        self::assertTrue($verdict->isClean());
        self::assertSame(Status::Clean, $verdict->status);
        self::assertSame(12, \count($verdict->outcomes));
    }

    public function testHoneypotBlocksSubmission(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        $verdict = $checker->checkRequest($this->request(['name' => 'bot', 'website' => 'filled']));

        self::assertTrue($verdict->isSpam());
        self::assertSame(['honeypot'], array_map(static fn($o): string => $o->check, $verdict->outcomes));
    }

    public function testLegacyCheckMethodIsKept(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        $verdict = $checker->check(['name' => 'Иван', 'email' => 'ivan@example.ru'], new \FormSpamChecker\Context('203.0.113.1', self::UA), 'contact');

        self::assertTrue($verdict->isClean());
    }

    public function testPerFormThresholdOverride(): void
    {
        $config = $this->config([
            'thresholds' => ['suspicious' => 30, 'spam' => 60],
            'forms' => ['register' => ['thresholds' => ['spam' => 45]]],
        ]);
        $checker = new SpamChecker($config, new MemoryStorage());

        $spammy = ['message' => 'casino betting bitcoin backlinks'];
        self::assertTrue($checker->checkRequest($this->request($spammy, 'contact'))->isSuspicious());
        self::assertTrue($checker->checkRequest($this->request($spammy, 'register'))->isSpam());
    }

    public function testCustomChecksAreUsed(): void
    {
        $check = new class implements SpamCheckInterface {
            public function name(): string
            {
                return 'always_spam';
            }

            public function check(RequestData $data): CheckOutcome
            {
                return CheckOutcome::spam('always_spam', 'custom');
            }
        };

        $checker = new SpamChecker($this->config(), new MemoryStorage(), [$check]);
        $verdict = $checker->checkRequest($this->request(['name' => 'x']));

        self::assertTrue($verdict->isSpam());
        self::assertSame('always_spam', $verdict->outcomes[0]->check);
    }

    public function testVerdictLogIsWrittenWithPii(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/verdicts.jsonl';
        $config = $this->config(['log' => ['enabled' => true, 'path' => $path, 'pii' => true]]);

        (new SpamChecker($config, new MemoryStorage()))->checkRequest(
            $this->request(['name' => 'Иван', 'website' => 'spam']),
        );

        self::assertFileExists($path);
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        $record = json_decode((string) $lines[0], true);
        self::assertSame('contact', $record['form']);
        self::assertSame('spam', $record['status']);
        self::assertSame('203.0.113.10', $record['ip']);
    }

    public function testDecisionIsLogFailureTolerant(): void
    {
        $config = $this->config(['log' => ['enabled' => true, 'path' => '']]);

        self::assertTrue((new SpamChecker($config, new MemoryStorage()))->checkRequest($this->request(['name' => 'Иван']))->isClean());
    }

    public function testFactoriesBuildExpectedImplementations(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory'], 'cache' => ['driver' => 'memory']]);
        $checker = new SpamChecker($config);

        self::assertInstanceOf(\FormSpamChecker\Storage\MemoryStorage::class, SpamChecker::createStorage($config));
        self::assertInstanceOf(\FormSpamChecker\Cache\ArrayCache::class, SpamChecker::createCache($config));
        self::assertInstanceOf(\FormSpamChecker\Dns\CachedResolver::class, SpamChecker::createDns($config));
        self::assertSame($config, $checker->config());
    }

    public function testCheckStatusSemantics(): void
    {
        self::assertTrue(CheckStatus::SPAM->isHardSpam());
        self::assertFalse(CheckStatus::HAM->isHardSpam());
        self::assertSame('uncertain', CheckStatus::UNCERTAIN->label());
    }
}
