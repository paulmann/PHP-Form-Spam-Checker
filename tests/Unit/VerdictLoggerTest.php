<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\Log\VerdictLogger;
use FormSpamChecker\Submission;
use FormSpamChecker\Verdict;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class VerdictLoggerTest extends TempDirTestCase
{
    public function testHashesIpAndRedactsFieldsByDefault(): void
    {
        $path = $this->tempDir() . '/nested/dir/verdicts.jsonl';
        $logger = new VerdictLogger($path);
        $submission = new Submission(
            ['name' => 'Иван', 'message' => 'Текст заявки'],
            new Context('203.0.113.55', 'UA', 'https://ref', '/page'),
            'contact',
        );
        $verdict = Verdict::fromResults([CheckResult::spam('honeypot', 'filled')], new Config());

        $logger->log($verdict, $submission);

        self::assertFileExists($path);
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        $record = json_decode((string) $lines[0], true);

        self::assertNotSame('203.0.113.55', $record['ip']);
        self::assertSame(16, strlen((string) $record['ip']));
        self::assertSame('redacted', $record['fields']);
        self::assertSame('spam', $record['status']);
        self::assertSame('filled', $record['checks'][0]['reason']);
    }

    public function testPiiModeStoresIpAndSamples(): void
    {
        $path = $this->tempDir() . '/verdicts.jsonl';
        $logger = new VerdictLogger($path, true, true);
        $submission = new Submission(['name' => 'Иван'], new Context('203.0.113.56', 'UA'), 'contact');

        $logger->log(Verdict::clean(), $submission);

        $record = json_decode((string) file($path)[0], true);
        self::assertSame('203.0.113.56', $record['ip']);
        self::assertSame(['name' => 'Иван'], $record['fields']);
    }

    public function testPathAccessor(): void
    {
        $path = $this->tempDir() . '/v.jsonl';
        $logger = new VerdictLogger($path);

        self::assertSame($path, $logger->path());
    }
}
