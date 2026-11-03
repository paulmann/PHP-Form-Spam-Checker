<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Log\VerdictLogger;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class VerdictLoggerV2Test extends TempDirTestCase
{
    public function testHashesIpAndRedactsFieldsByDefault(): void
    {
        $path = $this->tempDir() . '/nested/dir/verdicts.jsonl';
        $request = new RequestData(
            ['name' => 'Иван', 'message' => 'Текст заявки'],
            '203.0.113.55',
            [],
            [],
            [],
            'POST',
            '/page',
            '',
            1_700_000_000,
            'contact',
        );
        $verdict = Verdict::fromOutcomes([CheckOutcome::spam('honeypot', 'filled')], new Config(), true, 100);

        (new VerdictLogger($path))->log($verdict, $request);

        self::assertFileExists($path);
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        $record = json_decode((string) $lines[0], true);

        self::assertNotSame('203.0.113.55', $record['ip']);
        self::assertSame(16, \strlen((string) $record['ip']));
        self::assertSame('redacted', $record['fields']);
        self::assertSame('spam', $record['status']);
        self::assertSame('filled', $record['checks'][0]['reason']);
    }

    public function testPiiModeStoresIpAndSamplesWithExclusions(): void
    {
        $path = $this->tempDir() . '/verdicts.jsonl';
        $request = new RequestData(['name' => 'Иван', 'website' => 'x'], '203.0.113.56', [], [], [], 'POST', '/p', '', 1_700_000_000, 'contact');

        (new VerdictLogger($path, true, true, ['website']))->log(Verdict::clean(), $request);

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
