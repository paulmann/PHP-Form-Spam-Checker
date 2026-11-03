<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Check\SpfCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Tests\Unit\Dns\Fake\StubResolver;

final class SpfCheckTest extends NetworkTestCase
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

    public function testInvalidEmailAddressIsUncertain(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'not-an-email']));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame([], $this->dns->queries);
    }

    public function testMissingSpfRecordIsSuspiciousWithConfiguredScore(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(10, $outcome->score);
        self::assertSame('none', $outcome->evidence['example.com']['result']);
        self::assertStringContainsString('no v=spf1', $outcome->reason);
    }

    public function testValidRecordThatAuthorisesTheClientIsHam(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip4:203.0.113.0/24 -all'];

        $outcome = $this->check($this->enabled())->check($this->request(
            ip: '203.0.113.9',
            fields: ['email' => 'a@example.com'],
        ));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('pass', $outcome->evidence['example.com']['result']);
    }

    public function testValidRecordThatDoesNotAuthoriseTheClientStillCountsAsTrust(): void
    {
        // The visitor's IP is not the sending MTA: `fail` is not a domain problem.
        $this->dns->txtRecords['example.com'] = ['v=spf1 ip4:203.0.113.0/24 -all'];

        $outcome = $this->check($this->enabled())->check($this->request(
            ip: '198.51.100.1',
            fields: ['email' => 'a@example.com'],
        ));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('fail', $outcome->evidence['example.com']['result']);
    }

    public function testMultipleSpfRecordsAreSuspicious(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 -all', 'v=spf1 +all'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(10, $outcome->score);
        self::assertSame('permerror', $outcome->evidence['example.com']['result']);
    }

    public function testInvalidPolicyIsSuspicious(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 ptr -all'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(10, $outcome->score);
        self::assertSame('permerror', $outcome->evidence['example.com']['result']);
    }

    public function testWithoutClientIpOnlyRecordPresenceIsJudged(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 -all'];

        $outcome = $this->check($this->enabled())->check($this->request(
            ip: '',
            fields: ['email' => 'a@example.com'],
        ));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame('record-present', $outcome->evidence['example.com']['result']);
    }

    public function testWithoutClientIpAMissingRecordIsStillSuspicious(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(
            ip: '',
            fields: ['email' => 'a@example.com'],
        ));

        self::assertSame(10, $outcome->score);
        self::assertSame('missing', $outcome->evidence['example.com']['result']);
    }

    public function testEachMissingDomainAddsTheMissingScore(): void
    {
        // Two distinct reserved domains: one without an SPF record, one with a valid record.
        $this->dns->txtRecords['example.net'] = ['v=spf1 -all'];

        $outcome = $this->check($this->enabled())->check($this->request(fields: [
            'email' => 'a@example.org',
            'personalEmail' => 'b@example.net',
        ]));

        self::assertSame(10, $outcome->score);
        self::assertSame(['example.org' => 'none', 'example.net' => 'fail'], [
            'example.org' => $outcome->evidence['example.org']['result'],
            'example.net' => $outcome->evidence['example.net']['result'],
        ]);
        self::assertStringContainsString('example.org', $outcome->reason);
    }

    public function testConfiguredMissingScoreIsUsed(): void
    {
        $config = $this->enabled(['spf' => ['missing_score' => 25]]);

        $outcome = $this->check($config)->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(25, $outcome->score);
    }

    public function testScoreIsCappedAtOneHundred(): void
    {
        $config = $this->enabled(['spf' => ['missing_score' => 80]]);

        $outcome = $this->check($config)->check($this->request(fields: [
            'email' => 'a@example.org',
            'personalEmail' => 'b@example.net',
        ]));

        self::assertSame(100, $outcome->score);
    }

    public function testLookupLimitIsReadFromConfig(): void
    {
        $this->dns->txtRecords['example.com'] = ['v=spf1 include:a.example include:b.example -all'];
        $this->dns->txtRecords['a.example'] = ['v=spf1 -all'];
        $this->dns->txtRecords['b.example'] = ['v=spf1 -all'];

        $config = $this->enabled(['spf' => ['lookup_limit' => 1]]);
        $outcome = $this->check($config)->check($this->request(fields: ['email' => 'a@example.com']));

        self::assertSame(10, $outcome->score);
        self::assertSame('permerror', $outcome->evidence['example.com']['result']);
    }

    private function check(Config $config): SpfCheck
    {
        return new SpfCheck($this->dns, $config);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function enabled(array $overrides = []): Config
    {
        return $this->config(array_replace_recursive(['spf' => ['enabled' => true]], $overrides));
    }
}
