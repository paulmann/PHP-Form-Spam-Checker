<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Check\DmarcCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Tests\Unit\Dns\Fake\StubResolver;

final class DmarcCheckTest extends NetworkTestCase
{
    private StubResolver $dns;

    protected function setUp(): void
    {
        $this->dns = new StubResolver();
    }

    public function testDisabledCheckMakesNoDnsQuery(): void
    {
        $outcome = $this->check($this->config())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame('disabled', $outcome->reason);
        self::assertSame([], $this->dns->queries);
    }

    public function testNoEmailFieldIsUncertain(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request());

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame([], $this->dns->queries);
    }

    public function testMissingDmarcRecordIsSuspicious(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(10, $outcome->score);
        self::assertSame('missing', $outcome->evidence['example.com']['result']);
        self::assertStringContainsString('no DMARC record', $outcome->reason);
    }

    public function testWeakPolicyNoneIsSuspiciousWithWeakScore(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1; p=none; rua=mailto:dmarc@example.com'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(5, $outcome->score);
        self::assertSame('weak', $outcome->evidence['example.com']['result']);
        self::assertSame('none', $outcome->evidence['example.com']['policy']);
        self::assertStringContainsString('p=none', $outcome->reason);
    }

    public function testEnforcingRejectPolicyIsHam(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1; p=reject; adkim=s; aspf=s'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('ok', $outcome->evidence['example.com']['result']);
        self::assertSame('reject', $outcome->evidence['example.com']['policy']);
    }

    public function testEnforcingQuarantinePolicyIsHam(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1;p=quarantine'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('quarantine', $outcome->evidence['example.com']['policy']);
    }

    public function testPolicyIsCaseInsensitive(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['V=DMARC1; P=REJECT'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    public function testRecordWithoutPolicyTagIsInvalidAndSuspicious(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1; rua=mailto:dmarc@example.com'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(10, $outcome->score);
        self::assertSame('invalid', $outcome->evidence['example.com']['result']);
        self::assertStringContainsString('invalid DMARC record', $outcome->reason);
    }

    public function testMultipleDmarcRecordsAreInvalid(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1; p=reject', 'v=DMARC1; p=none'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(10, $outcome->score);
        self::assertSame('invalid', $outcome->evidence['example.com']['result']);
    }

    public function testUnrelatedTxtRecordsMeanMissingDmarc(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['google-site-verification=abc123'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(10, $outcome->score);
        self::assertSame('missing', $outcome->evidence['example.com']['result']);
    }

    public function testConfiguredScoresAreAggregatedPerDomain(): void
    {
        // Two distinct reserved domains: one with no DMARC record, one with p=none.
        $config = $this->enabled(['dmarc' => ['missing_score' => 20, 'weak_policy_score' => 7]]);
        $this->dns->txtRecords['_dmarc.example.net'] = ['v=DMARC1; p=none'];

        $outcome = $this->check($config)->check($this->request(fields: [
            'email' => 'a@example.org',
            'personalEmail' => 'b@example.net',
        ]));

        self::assertSame(27, $outcome->score);
        self::assertSame('missing', $outcome->evidence['example.org']['result']);
        self::assertSame('weak', $outcome->evidence['example.net']['result']);
    }

    public function testDomainIsTakenFromADisplayNameAddress(): void
    {
        $this->dns->txtRecords['_dmarc.example.com'] = ['v=DMARC1; p=reject'];

        $outcome = $this->check($this->enabled())->check($this->request(
            fields: ['email' => 'John Doe <john@Example.COM>'],
        ));

        self::assertSame(0, $outcome->score);
        self::assertArrayHasKey('example.com', $outcome->evidence);
        self::assertSame(['txt:_dmarc.example.com'], $this->dns->queries);
    }

    private function check(Config $config): DmarcCheck
    {
        return new DmarcCheck($this->dns, $config);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function enabled(array $overrides = []): Config
    {
        return $this->config(array_replace_recursive(['dmarc' => ['enabled' => true]], $overrides));
    }
}
