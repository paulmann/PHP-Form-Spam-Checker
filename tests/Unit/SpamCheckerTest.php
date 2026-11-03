<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Status;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Log\VerdictLogger;

final class SpamCheckerTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    public function testCleanSubmissionPassesTheDefaultPipeline(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        $verdict = $checker->check(
            [
                'name' => 'Иван Петров',
                'company' => 'ООО Энергосервис',
                'email' => 'ivan@example.ru',
                'phone' => '+7 999 000-00-00',
                'message' => 'Нужен отчёт по протоколу испытаний за октябрь.',
            ],
            new Context('203.0.113.10', self::UA, 'https://example.ru/contacts/', '/contacts/'),
            'contact',
        );

        self::assertTrue($verdict->isClean());
        self::assertSame(Status::Clean, $verdict->status);
    }

    public function testHoneypotInDefaultPipelineBlocksTheSubmission(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        $verdict = $checker->check(
            ['name' => 'bot', 'email' => 'bot@example.ru', 'website' => 'http://spam.example'],
            new Context('203.0.113.10', self::UA),
            'contact',
        );

        self::assertTrue($verdict->isSpam());
        self::assertNotEmpty($verdict->reasons());
    }

    public function testPerFormOverrideIsApplied(): void
    {
        $config = new Config([
            'rate_limit' => ['max' => 10],
            'forms' => [
                'register' => ['rate_limit' => ['max' => 1]],
            ],
        ]);

        $checker = new SpamChecker($config, new MemoryStorage());
        $context = new Context('203.0.113.20', self::UA);

        self::assertTrue($checker->check(['name' => 'A'], $context, 'register')->isClean());
        self::assertTrue($checker->check(['name' => 'A'], $context, 'register')->isSpam());
        self::assertTrue($checker->check(['name' => 'A'], $context, 'contact')->isClean());
    }

    public function testCustomChecksAreUsed(): void
    {
        $check = new class implements CheckInterface {
            public function name(): string
            {
                return 'always_spam';
            }

            public function check(\FormSpamChecker\Submission $submission): CheckResult
            {
                return CheckResult::spam('always_spam', 'custom check');
            }
        };

        $checker = new SpamChecker(new Config(), new MemoryStorage(), [$check]);
        $verdict = $checker->check(['name' => 'x'], new Context());

        self::assertTrue($verdict->isSpam());
        self::assertSame('always_spam', $verdict->results[0]->check);
    }

    public function testVerdictLoggerWritesJsonLine(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/verdicts.jsonl';

        $config = new Config([
            'log' => ['enabled' => true, 'path' => $path, 'pii' => true],
        ]);

        $checker = new SpamChecker($config, new MemoryStorage());
        $checker->check(['name' => 'x', 'website' => 'spam'], new Context('203.0.113.30', 'UA'), 'contact');

        self::assertFileExists($path);
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        self::assertCount(1, $lines);

        $record = json_decode((string) $lines[0], true);
        self::assertIsArray($record);
        self::assertSame('contact', $record['form']);
        self::assertSame('spam', $record['status']);
        self::assertSame('203.0.113.30', $record['ip']);
    }

    public function testLoggerIsOptional(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());

        self::assertTrue(
            $checker->check(['name' => 'x'], new Context('203.0.113.1', self::UA))->isClean(),
        );
    }

    public function testCheckSubmissionUsesSubmissionFormId(): void
    {
        $checker = new SpamChecker($this->config(), new MemoryStorage());
        $submission = new \FormSpamChecker\Submission(
            ['name' => 'x', 'email' => 'ivan@example.ru'],
            new Context('203.0.113.1', self::UA),
            'register',
        );

        self::assertTrue($checker->checkSubmission($submission)->isClean());
    }

    public function testFromConfigFactory(): void
    {
        $checker = SpamChecker::fromConfig($this->config(), new MemoryStorage());

        self::assertInstanceOf(SpamChecker::class, $checker);
        self::assertSame(60, $checker->config()->int('thresholds.spam'));
    }

    private function config(): Config
    {
        return new Config([
            'storage' => ['driver' => 'memory'],
            'user_agent' => ['allow_empty' => false],
        ]);
    }
}
