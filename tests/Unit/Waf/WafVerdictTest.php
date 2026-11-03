<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf;

use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafVerdict;
use PHPUnit\Framework\TestCase;

final class WafVerdictTest extends TestCase
{
    public function testToArrayExposesFindingsAndReasons(): void
    {
        $finding = new WafFinding(
            rule: 'sql_injection',
            severity: 90,
            hard: true,
            reason: 'SQL-injection signature detected',
            evidence: ['pattern' => '#union#'],
            location: 'field.message',
        );

        $verdict = new WafVerdict(true, 90, [$finding], WafVerdict::STATUS_BLOCKED);

        $array = $verdict->toArray();

        self::assertTrue($array['blocked']);
        self::assertSame('blocked', $array['status']);
        self::assertSame(90, $array['score']);
        self::assertSame(['sql_injection: SQL-injection signature detected'], $array['reasons']);
        self::assertSame('sql_injection', $array['findings'][0]['rule']);
        self::assertSame('field.message', $array['findings'][0]['location']);
        self::assertSame(['pattern' => '#union#'], $array['findings'][0]['evidence']);
    }

    public function testCleanFactoryHasNoFindings(): void
    {
        $verdict = WafVerdict::clean();

        self::assertFalse($verdict->blocked);
        self::assertSame(0, $verdict->score);
        self::assertSame([], $verdict->findings);
        self::assertSame([], $verdict->reasons());
        self::assertTrue($verdict->isClean());
        self::assertFalse($verdict->isSuspicious());
        self::assertFalse($verdict->isBlocked());
    }

    public function testReasonsAndRuleNamesAreUnique(): void
    {
        $first = new WafFinding('scanner', 40, false, 'scanner path requested');
        $second = new WafFinding('scanner', 40, false, 'scanner path requested');
        $third = new WafFinding('xss', 50, false, 'XSS signature detected');

        $verdict = new WafVerdict(false, 90, [$first, $second, $third], WafVerdict::STATUS_SUSPICIOUS);

        self::assertCount(2, $verdict->reasons());
        self::assertSame(['scanner', 'xss'], $verdict->ruleNames());
        self::assertTrue($verdict->isSuspicious());
    }

    public function testScoreOutOfRangeIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WafVerdict(true, 101, [], WafVerdict::STATUS_BLOCKED);
    }

    public function testUnknownStatusIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WafVerdict(false, 0, [], 'unknown');
    }

    public function testFindingSeverityOutOfRangeIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new WafFinding('xss', 101, true, 'too severe');
    }
}
