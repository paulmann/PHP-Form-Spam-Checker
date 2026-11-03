<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf\Rules;

use FormSpamChecker\Config;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Unit\Waf\WafTestCase;
use FormSpamChecker\Waf\Rules\RateLimitRule;

final class RateLimitRuleTest extends WafTestCase
{
    public function testRuleIsDisabledByDefault(): void
    {
        $rule = new RateLimitRule(new Config(), new MemoryStorage(1_700_000_000));

        self::assertFalse($rule->enabled());
        self::assertNull($rule->inspect($this->request(ip: '203.0.113.9')));
    }

    public function testRequestOverTheLimitIsAHardFinding(): void
    {
        $rule = new RateLimitRule($this->enabledConfig(max: 2, window: 60), new MemoryStorage(1_700_000_000));
        $request = $this->request(ip: '203.0.113.9');

        $first = $rule->inspect($request);
        self::assertNull($first);
        $second = $rule->inspect($request);
        self::assertNull($second);

        $finding = $rule->inspect($request);

        $this->assertHardFinding($finding, 'rate_limit');
        self::assertSame(80, $finding->severity);
        self::assertSame('ip', $finding->location);
        self::assertSame(3, $finding->evidence['count']);
        self::assertSame(2, $finding->evidence['max']);
    }

    public function testLimitIsPerIp(): void
    {
        $rule = new RateLimitRule($this->enabledConfig(max: 1, window: 60), new MemoryStorage(1_700_000_000));

        self::assertNull($rule->inspect($this->request(ip: '203.0.113.9')));
        self::assertNotNull($rule->inspect($this->request(ip: '203.0.113.9')));
        self::assertNull($rule->inspect($this->request(ip: '203.0.113.10')));
    }

    public function testWindowExpiresWithTheStorageClock(): void
    {
        $storage = new MemoryStorage(1_700_000_000);
        $rule = new RateLimitRule($this->enabledConfig(max: 1, window: 60), $storage);
        $request = $this->request(ip: '203.0.113.9');

        self::assertNull($rule->inspect($request));
        self::assertNotNull($rule->inspect($request));

        $storage->travel(61);

        self::assertNull($rule->inspect($request));
    }

    public function testEnabledRuleWithoutStorageIsSilent(): void
    {
        $rule = new RateLimitRule($this->enabledConfig(max: 1, window: 60), null);

        self::assertNull($rule->inspect($this->request(ip: '203.0.113.9')));
        self::assertNull($rule->inspect($this->request(ip: '203.0.113.9')));
    }

    public function testRequestWithoutIpIsIgnored(): void
    {
        $rule = new RateLimitRule($this->enabledConfig(max: 1, window: 60), new MemoryStorage(1_700_000_000));

        self::assertNull($rule->inspect($this->request(ip: '')));
        self::assertNull($rule->inspect($this->request(ip: '')));
    }

    public function testSeverityIsConfigurable(): void
    {
        $rule = new RateLimitRule(
            $this->enabledConfig(max: 1, window: 60, options: ['severity' => 50]),
            new MemoryStorage(1_700_000_000),
        );
        $request = $this->request(ip: '203.0.113.9');

        $first = $rule->inspect($request);
        self::assertNull($first);

        $finding = $rule->inspect($request);
        self::assertNotNull($finding);
        self::assertSame(50, $finding->severity);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function enabledConfig(int $max, int $window, array $options = []): Config
    {
        return new Config([
            'waf' => ['rules' => ['rate_limit' => ['enabled' => true, 'max' => $max, 'window' => $window] + $options]],
        ]);
    }
}
