<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Verdict;
use PHPUnit\Framework\TestCase;

final class VerdictTest extends TestCase
{
    public function testCleanResultsProduceCleanVerdict(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::clean('honeypot'),
            CheckResult::clean('user_agent'),
        ], new Config());

        self::assertTrue($verdict->isClean());
        self::assertSame(0, $verdict->score);
        self::assertSame([], $verdict->reasons());
    }

    public function testScoresBelowThresholdStayClean(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::suspicious('keywords', 20, 'one hit'),
        ], new Config());

        self::assertTrue($verdict->isClean());
    }

    public function testScoresAboveSuspiciousThresholdAreSuspicious(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::suspicious('keywords', 35, 'three hits'),
        ], new Config());

        self::assertTrue($verdict->isSuspicious());
        self::assertSame(Status::Suspicious, $verdict->status);
    }

    public function testScoresAboveSpamThresholdAreSpam(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::suspicious('keywords', 40, 'spam words'),
            CheckResult::suspicious('links', 25, 'too many links'),
        ], new Config());

        self::assertTrue($verdict->isSpam());
        self::assertSame(65, $verdict->score);
    }

    public function testHardSpamWinsRegardlessOfScore(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::clean('honeypot'),
            new CheckResult('custom', Status::Spam, 1, 'hard evidence'),
        ], new Config());

        self::assertTrue($verdict->isSpam());
    }

    public function testScoreIsCappedAtOneHundred(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::suspicious('a', 80, 'a'),
            CheckResult::suspicious('b', 80, 'b'),
        ], new Config());

        self::assertSame(100, $verdict->score);
    }

    public function testReasonsIncludeFlaggedChecksOnly(): void
    {
        $verdict = Verdict::fromResults([
            CheckResult::clean('honeypot', 'empty'),
            CheckResult::spam('xss', 'script tag'),
            CheckResult::suspicious('links', 20, 'link count'),
        ], new Config());

        self::assertSame(['xss: script tag', 'links: link count'], $verdict->reasons());
        self::assertCount(2, $verdict->flagged());
    }

    public function testVerdictArrayRoundTrip(): void
    {
        $original = Verdict::fromResults([
            CheckResult::spam('honeypot', 'filled', ['fields' => ['website' => 'x']]),
        ], new Config());

        $restored = Verdict::fromArray($original->toArray());

        self::assertSame($original->status, $restored->status);
        self::assertSame($original->score, $restored->score);
        self::assertSame($original->reasons(), $restored->reasons());
        self::assertCount(1, $restored->results);
        self::assertSame(['website' => 'x'], $restored->results[0]->evidence['fields']);
    }

    public function testInvalidScoreIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Verdict(Status::Clean, 101);
    }

    public function testCheckResultRejectsOutOfRangeScores(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CheckResult('broken', Status::Clean, 150);
    }

    public function testFromArrayToleratesUnknownStatus(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Verdict::fromArray(['status' => 'unknown', 'score' => 0, 'checks' => []]);
    }
}
