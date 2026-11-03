<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Dns;

use FormSpamChecker\Support\SpfEvaluator;
use FormSpamChecker\Support\SpfResult;
use FormSpamChecker\Tests\Unit\Dns\Fake\StubResolver;
use PHPUnit\Framework\TestCase;

final class SpfEvaluatorTest extends TestCase
{
    private StubResolver $dns;

    protected function setUp(): void
    {
        $this->dns = new StubResolver();
    }

    public function testIp4MechanismMatchesAndPasses(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip4:203.0.113.0/24 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
        self::assertTrue($result->isPass());
        self::assertSame('example.com', $result->domain);
    }

    public function testUnmatchedMechanismFallsThroughToTheAllQualifier(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip4:203.0.113.0/24 -all'];

        $result = $this->evaluator()->evaluate('example.com', '198.51.100.1');

        self::assertSame(SpfResult::FAIL, $result->result);
        self::assertTrue($result->isFail());
    }

    public function testSoftfailQualifier(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ~all'];

        self::assertSame(SpfResult::SOFTFAIL, $this->evaluator()->evaluate('example.com', '203.0.113.9')->result);
    }

    public function testNeutralQualifier(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ?all'];

        self::assertSame(SpfResult::NEUTRAL, $this->evaluator()->evaluate('example.com', '203.0.113.9')->result);
    }

    public function testBareAllMechanismPassesByDefault(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 +all'];

        self::assertSame(SpfResult::PASS, $this->evaluator()->evaluate('example.com', '203.0.113.9')->result);
    }

    public function testNoMatchingMechanismWithoutAllIsNeutral(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip4:192.0.2.1'];

        self::assertSame(SpfResult::NEUTRAL, $this->evaluator()->evaluate('example.com', '203.0.113.9')->result);
    }

    public function testQualifiersOnIp4Mechanism(): void
    {
        $this->dns->txtRecords['fails.example'] = ['v=spf1 -ip4:203.0.113.9'];
        $this->dns->txtRecords['soft.example'] = ['v=spf1 ~ip4:203.0.113.9'];
        $this->dns->txtRecords['neutral.example'] = ['v=spf1 ?ip4:203.0.113.9'];
        $this->dns->txtRecords['pass.example'] = ['v=spf1 +ip4:203.0.113.9'];

        $evaluator = $this->evaluator();

        self::assertSame(SpfResult::FAIL, $evaluator->evaluate('fails.example', '203.0.113.9')->result);
        self::assertSame(SpfResult::SOFTFAIL, $evaluator->evaluate('soft.example', '203.0.113.9')->result);
        self::assertSame(SpfResult::NEUTRAL, $evaluator->evaluate('neutral.example', '203.0.113.9')->result);
        self::assertSame(SpfResult::PASS, $evaluator->evaluate('pass.example', '203.0.113.9')->result);
    }

    public function testIp6MechanismMatches(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip6:2001:db8::/32 -all'];

        $result = $this->evaluator()->evaluate('example.com', '2001:db8::1');

        self::assertSame(SpfResult::PASS, $result->result);
    }

    public function testAMechanismMatchesResolvedAddress(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 a:mail.example.com -all'];
        $this->dns->aRecords['mail.example.com'] = ['203.0.113.9'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
        self::assertContains('a:mail.example.com', $this->dns->queries);
    }

    public function testAMechanismWithCidrSuffix(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 a/24 -all'];
        $this->dns->aRecords['example.com'] = ['203.0.113.5'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
    }

    public function testMxMechanismMatchesTheMxHostAddress(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 mx -all'];
        $this->dns->mxRecords['example.com'] = ['mail.example.com'];
        $this->dns->aRecords['mail.example.com'] = ['203.0.113.9'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
        self::assertContains('mx:example.com', $this->dns->queries);
    }

    public function testIncludeThatPassesMakesTheRootPass(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:_spf.example.net -all'];
        $this->dns->txtRecords['_spf.example.net'] = ['v=spf1 ip4:203.0.113.9 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
        self::assertSame(1, $result->lookups);
    }

    public function testIncludeThatDoesNotMatchFallsThrough(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:_spf.example.net -all'];
        $this->dns->txtRecords['_spf.example.net'] = ['v=spf1 ip4:192.0.2.1 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::FAIL, $result->result);
    }

    public function testIncludeWithoutARecordIsAPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:_spf.example.net -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
        self::assertTrue($result->isPermError());
    }

    public function testIncludePropagatesATargetPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:_spf.example.net -all'];
        $this->dns->txtRecords['_spf.example.net'] = ['v=spf1 -all', 'v=spf1 +all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
    }

    public function testRedirectIsUsedWhenNoMechanismMatches(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 redirect=_spf.example.net'];
        $this->dns->txtRecords['_spf.example.net'] = ['v=spf1 ip4:203.0.113.9 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
    }

    public function testRedirectTargetWithoutARecordIsAPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 redirect=_spf.example.net'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
    }

    public function testLookupLimitExhaustionIsAPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:a.example include:b.example include:c.example -all'];
        $this->dns->txtRecords['a.example'] = ['v=spf1 -all'];
        $this->dns->txtRecords['b.example'] = ['v=spf1 -all'];

        $result = $this->evaluator(lookupLimit: 2)->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
        self::assertStringContainsString('lookup limit', $result->reason);
    }

    public function testDefaultLookupLimitAllowsTenQueries(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:a.example -all'];
        $this->dns->txtRecords['a.example'] = ['v=spf1 include:b.example -all'];
        $this->dns->txtRecords['b.example'] = ['v=spf1 ip4:203.0.113.9 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PASS, $result->result);
        self::assertSame(2, $result->lookups);
    }

    public function testRedirectLoopDegradesToAPermError(): void
    {
        $this->dns->txtRecords['a.example'] = ['v=spf1 redirect=b.example'];
        $this->dns->txtRecords['b.example'] = ['v=spf1 redirect=a.example'];

        $result = $this->evaluator(lookupLimit: 100)->evaluate('a.example', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
    }

    public function testMultipleRecordsAreAPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 -all', 'v=spf1 +all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::PERMERROR, $result->result);
        self::assertStringContainsString('multiple', $result->reason);
    }

    public function testUnknownMechanismIsAPermError(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ptr -all'];

        self::assertSame(SpfResult::PERMERROR, $this->evaluator()->evaluate('example.com', '203.0.113.9')->result);
    }

    public function testUnknownModifierAndExpAreIgnored(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 exp=explain.example.com x-custom=1 -all'];

        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::FAIL, $result->result);
        self::assertNotContains('txt:explain.example.com', $this->dns->queries);
    }

    public function testMissingRecordIsNone(): void
    {
        $result = $this->evaluator()->evaluate('example.com', '203.0.113.9');

        self::assertSame(SpfResult::NONE, $result->result);
        self::assertTrue($result->isNone());
    }

    public function testInvalidClientAddressIsNone(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 -all'];

        $result = $this->evaluator()->evaluate('example.com', 'not-an-ip');

        self::assertSame(SpfResult::NONE, $result->result);
        self::assertSame([], $this->dns->queries);
    }

    public function testInvalidDomainIsNone(): void
    {
        self::assertSame(SpfResult::NONE, $this->evaluator()->evaluate('', '203.0.113.9')->result);
    }

    public function testRecordMatchingIsCaseInsensitive(): void
    {
        $this->dns->txtRecords['example.com'] = ['V=SPF1 IP4:203.0.113.9 -ALL'];

        self::assertSame(SpfResult::PASS, $this->evaluator()->evaluate('Example.COM', '203.0.113.9')->result);
    }

    public function testSpfRecordsFiltersUnrelatedTxtValues(): void
    {
        $this->dns->txtRecords['example.com'] = [
            'google-site-verification=abc',
            'v=spf1 -all',
            '',
        ];

        $records = $this->evaluator()->spfRecords('example.com');

        self::assertSame(['v=spf1 -all'], $records);
    }

    public function testSpfRecordsExposesEveryRecordForDuplicateDetection(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 -all', 'v=spf1 +all'];

        self::assertCount(2, $this->evaluator()->spfRecords('example.com'));
    }

    private function evaluator(int $lookupLimit = SpfEvaluator::DEFAULT_LOOKUP_LIMIT): SpfEvaluator
    {
        return new SpfEvaluator($this->dns, $lookupLimit);
    }
}
