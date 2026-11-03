<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\IpReputationRule;

final class IpReputationRuleTest extends WafTestCase
{
    public function testRuleIsDisabledByDefault(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::spam('abuseipdb', 'listed', [], 100));
        $rule = new IpReputationRule(new Config(), $check);

        self::assertFalse($rule->enabled());
        self::assertNull($rule->inspect($this->request(ip: '198.51.100.9')));
        self::assertNull($check->seen);
    }

    public function testSpamScoreAtOrAboveThresholdIsHard(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::spam('abuseipdb', 'listed', ['confidence' => 100], 100));
        $rule = new IpReputationRule($this->enabledConfig(), $check);

        $finding = $rule->inspect($this->request(ip: '198.51.100.9'));

        $this->assertHardFinding($finding, 'ip_reputation');
        self::assertSame(100, $finding->severity);
        self::assertSame('ip', $finding->location);
        self::assertSame('abuseipdb', $finding->evidence['check']);
        self::assertSame('spam', $finding->evidence['status']);
    }

    public function testSpamScoreBelowThresholdIsScoreOnly(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::spam('abuseipdb', 'listed', [], 70));
        $rule = new IpReputationRule($this->enabledConfig(), $check);

        $finding = $rule->inspect($this->request(ip: '198.51.100.9'));

        self::assertNotNull($finding);
        self::assertFalse($finding->hard);
        self::assertSame(70, $finding->severity);
    }

    public function testSuspiciousHamOutcomeIsScoreOnly(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::suspicious('abuseipdb', 40, 'some reports'));
        $rule = new IpReputationRule($this->enabledConfig(), $check);

        $finding = $rule->inspect($this->request(ip: '198.51.100.9'));

        self::assertNotNull($finding);
        self::assertFalse($finding->hard);
        self::assertSame(40, $finding->severity);
    }

    public function testErrorAndUncertainOutcomesFailOpen(): void
    {
        $error = new FakeIpReputationCheck(CheckOutcome::error('abuseipdb', 'timeout'));
        $uncertain = new FakeIpReputationCheck(CheckOutcome::uncertain('abuseipdb', 'no data'));
        $clean = new FakeIpReputationCheck(CheckOutcome::ham('abuseipdb', 'clean'));

        $request = $this->request(ip: '198.51.100.9');

        self::assertNull((new IpReputationRule($this->enabledConfig(), $error))->inspect($request));
        self::assertNull((new IpReputationRule($this->enabledConfig(), $uncertain))->inspect($request));
        self::assertNull((new IpReputationRule($this->enabledConfig(), $clean))->inspect($request));
    }

    public function testOnlyTheIpIsHandedToTheCollaborator(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::ham('abuseipdb', 'clean'));
        $rule = new IpReputationRule($this->enabledConfig(), $check);

        $rule->inspect($this->request(
            method: 'POST',
            uri: '/contact',
            fields: ['message' => 'private message'],
            body: 'message=private',
            cookies: ['sid' => 'secret'],
            query: ['q' => 'secret'],
            ip: '198.51.100.9',
        ));

        $seen = $check->seen;
        self::assertNotNull($seen);
        self::assertSame('198.51.100.9', $seen->ip);
        self::assertSame([], $seen->fields);
        self::assertSame([], $seen->headers);
        self::assertSame([], $seen->cookies);
        self::assertSame([], $seen->query);
        self::assertSame('', $seen->body);
        self::assertSame('', $seen->uri);
    }

    public function testInvalidIpIsIgnored(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::spam('abuseipdb', 'listed', [], 100));
        $rule = new IpReputationRule($this->enabledConfig(), $check);

        self::assertNull($rule->inspect($this->request(ip: '')));
        self::assertNull($rule->inspect($this->request(ip: 'not-an-ip')));
        self::assertNull($check->seen);
    }

    public function testEnabledRuleWithoutCollaboratorIsSilent(): void
    {
        $rule = new IpReputationRule($this->enabledConfig(), null);

        self::assertNull($rule->inspect($this->request(ip: '198.51.100.9')));
    }

    public function testThresholdIsConfigurable(): void
    {
        $check = new FakeIpReputationCheck(CheckOutcome::spam('abuseipdb', 'listed', [], 80));
        $rule = new IpReputationRule($this->enabledConfig(['threshold' => 100]), $check);

        // Score 80 is below the configured 100, so the finding stays soft.
        $finding = $rule->inspect($this->request(ip: '198.51.100.9'));

        self::assertNotNull($finding);
        self::assertFalse($finding->hard);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function enabledConfig(array $options = []): Config
    {
        return new Config([
            'waf' => ['rules' => ['ip_reputation' => ['enabled' => true] + $options]],
        ]);
    }
}

final class FakeIpReputationCheck implements SpamCheckInterface
{
    public ?RequestData $seen = null;

    public function __construct(private readonly CheckOutcome $outcome) {}

    public function name(): string
    {
        return 'abuseipdb';
    }

    public function check(RequestData $data): CheckOutcome
    {
        $this->seen = $data;

        return $this->outcome;
    }
}
