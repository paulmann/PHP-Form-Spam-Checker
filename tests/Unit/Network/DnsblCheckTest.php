<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Check\DnsblCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Tests\Unit\Dns\Fake\StubResolver;

final class DnsblCheckTest extends NetworkTestCase
{
    private StubResolver $dns;

    protected function setUp(): void
    {
        $this->dns = new StubResolver();
    }

    public function testDisabledCheckMakesNoDnsQuery(): void
    {
        $outcome = $this->check($this->config())->check($this->request());

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame('disabled', $outcome->reason);
        self::assertSame([], $this->dns->queries);
    }

    public function testMissingIpIsUncertain(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(ip: ''));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame([], $this->dns->queries);
    }

    public function testInvalidIpIsUncertain(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(ip: '999.0.0.1'));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertSame([], $this->dns->queries);
    }

    public function testCleanIpIsHamAndEveryZoneIsQueried(): void
    {
        $outcome = $this->check($this->enabled())->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
        self::assertSame(
            ['a:9.113.0.203.zen.spamhaus.org', 'a:9.113.0.203.bl.spamcop.net'],
            $this->dns->queries,
        );
        self::assertSame(['zen.spamhaus.org', 'bl.spamcop.net'], $outcome->evidence['zones_checked']);
    }

    public function testListingInTheFirstZoneIsHardSpamAndStopsFurtherZones(): void
    {
        $this->dns->aRecords['9.113.0.203.zen.spamhaus.org'] = ['127.0.0.2'];

        $outcome = $this->check($this->enabled())->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(100, $outcome->score);
        self::assertSame(['a:9.113.0.203.zen.spamhaus.org'], $this->dns->queries);
        self::assertSame(['zen.spamhaus.org' => ['127.0.0.2']], $outcome->evidence['hits']);
    }

    public function testListingInTheSecondZoneIsDetected(): void
    {
        $this->dns->aRecords['9.113.0.203.bl.spamcop.net'] = ['127.0.0.4'];

        $outcome = $this->check($this->enabled())->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertCount(2, $this->dns->queries);
        self::assertSame(['bl.spamcop.net' => ['127.0.0.4']], $outcome->evidence['hits']);
    }

    public function testAnswersOutsideTheListingRangeAreNotHits(): void
    {
        $this->dns->aRecords['9.113.0.203.zen.spamhaus.org'] = ['198.51.100.7', '0.0.0.0'];
        $this->dns->aRecords['9.113.0.203.bl.spamcop.net'] = ['127.0.1.2'];

        $outcome = $this->check($this->enabled())->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
    }

    public function testConfiguredHitScoreIsUsed(): void
    {
        $this->dns->aRecords['9.113.0.203.zen.spamhaus.org'] = ['127.0.0.2'];
        $config = $this->config(['dnsbl' => ['enabled' => true, 'hit_score' => 40]]);

        $outcome = $this->check($config)->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame(40, $outcome->score);
    }

    public function testHitScoreIsClampedToTheOutcomeRange(): void
    {
        $this->dns->aRecords['9.113.0.203.zen.spamhaus.org'] = ['127.0.0.2'];
        $config = $this->config(['dnsbl' => ['enabled' => true, 'hit_score' => 250]]);

        $outcome = $this->check($config)->check($this->request(ip: '203.0.113.9'));

        self::assertSame(100, $outcome->score);
    }

    public function testNoConfiguredZonesIsUncertain(): void
    {
        $config = $this->config(['dnsbl' => ['enabled' => true, 'zones' => []]]);

        $outcome = $this->check($config)->check($this->request(ip: '203.0.113.9'));

        self::assertSame(CheckStatus::UNCERTAIN, $outcome->status);
        self::assertStringContainsString('zones', $outcome->reason);
        self::assertSame([], $this->dns->queries);
    }

    public function testZoneNamesAreNormalised(): void
    {
        $config = $this->config(['dnsbl' => ['enabled' => true, 'zones' => ['ZEN.Spamhaus.ORG.']]]);

        $this->check($config)->check($this->request(ip: '203.0.113.9'));

        self::assertSame(['a:9.113.0.203.zen.spamhaus.org'], $this->dns->queries);
    }

    public function testResolvedEmptyAnswersAreHamNotAnError(): void
    {
        // A broken resolver answers nothing at all: the submission must not be punished.
        $outcome = $this->check($this->enabled())->check($this->request(ip: '198.51.100.23'));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(0, $outcome->score);
    }

    public function testIpv6AddressUsesTheNibbleFormat(): void
    {
        $lookupName = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2';
        $this->dns->aRecords[$lookupName . '.zen.spamhaus.org'] = ['127.0.0.2'];

        $outcome = $this->check($this->enabled())->check($this->request(ip: '2001:db8::1'));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame('a:' . $lookupName . '.zen.spamhaus.org', $this->dns->queries[0]);
    }

    private function check(Config $config): DnsblCheck
    {
        return new DnsblCheck($this->dns, $config);
    }

    private function enabled(): Config
    {
        return $this->config(['dnsbl' => ['enabled' => true]]);
    }
}
