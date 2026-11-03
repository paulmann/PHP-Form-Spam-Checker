<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Pipeline;
use FormSpamChecker\Status;
use FormSpamChecker\Submission;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class PipelineTest extends TestCase
{
    use BuildsSubmissions;

    public function testResultsAreAggregated(): void
    {
        $pipeline = new Pipeline([
            $this->fixedCheck('a', CheckResult::suspicious('a', 20, 'a hit')),
            $this->fixedCheck('b', CheckResult::suspicious('b', 45, 'b hit')),
        ]);

        $verdict = $pipeline->run($this->submission([]), new Config());

        self::assertTrue($verdict->isSpam());
        self::assertSame(65, $verdict->score);
        self::assertCount(2, $verdict->results);
    }

    public function testExceptionInCheckFailsOpen(): void
    {
        $pipeline = new Pipeline([
            $this->fixedCheck('exploding', null),
            $this->fixedCheck('clean', CheckResult::clean('clean')),
        ]);

        $verdict = $pipeline->run($this->submission([]), new Config());

        self::assertTrue($verdict->isClean());
        self::assertSame('check error (fail open): boom', $verdict->results[0]->reason);
    }

    public function testChecksAccessor(): void
    {
        $check = $this->fixedCheck('one', CheckResult::clean('one'));
        $pipeline = new Pipeline([$check]);

        self::assertSame([$check], $pipeline->checks());
    }

    private function fixedCheck(string $name, ?CheckResult $result): CheckInterface
    {
        return new class ($name, $result) implements CheckInterface {
            public function __construct(
                private readonly string $checkName,
                private readonly ?CheckResult $result,
            ) {
            }

            public function name(): string
            {
                return $this->checkName;
            }

            public function check(Submission $submission): CheckResult
            {
                if ($this->result === null) {
                    throw new \RuntimeException('boom');
                }

                return $this->result;
            }
        };
    }
}
