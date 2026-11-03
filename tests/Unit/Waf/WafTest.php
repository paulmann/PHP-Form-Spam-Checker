<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Waf;

use FormSpamChecker\Config;
use FormSpamChecker\Log\LoggerInterface;
use FormSpamChecker\Waf\RuleInterface;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;
use FormSpamChecker\Waf\WafVerdict;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class WafTest extends TestCase
{
    public function testDefaultRuleSetHasEveryBuiltInRuleInOrder(): void
    {
        $waf = Waf::withDefaultRules(new Config());

        self::assertSame(
            [
                'sql_injection',
                'xss',
                'path_traversal',
                'command_injection',
                'scanner',
                'header_injection',
                'protocol',
                'ip_reputation',
                'rate_limit',
            ],
            array_map(static fn(RuleInterface $rule): string => $rule->name(), $waf->rules()),
        );
    }

    public function testCleanRequestProducesCleanVerdict(): void
    {
        $waf = new Waf(new Config(), []);

        $verdict = $waf->inspect(new WafRequest());

        self::assertSame(WafVerdict::STATUS_CLEAN, $verdict->status);
        self::assertFalse($verdict->blocked);
        self::assertSame(0, $verdict->score);
        self::assertSame([], $verdict->findings);
    }

    public function testHardFindingBlocksRegardlessOfTheScore(): void
    {
        $waf = new Waf(new Config(), [self::stubRule('sql_injection', self::finding('sql_injection', 10, true))]);

        $verdict = $waf->inspect(new WafRequest());

        self::assertTrue($verdict->blocked);
        self::assertSame(WafVerdict::STATUS_BLOCKED, $verdict->status);
        self::assertSame(10, $verdict->score);
    }

    public function testSoftFindingsAccumulateToSuspicious(): void
    {
        $waf = new Waf(new Config(), [
            self::stubRule('first', self::finding('first', 20, false)),
            self::stubRule('second', self::finding('second', 20, false)),
        ]);

        $verdict = $waf->inspect(new WafRequest());

        self::assertFalse($verdict->blocked);
        self::assertSame(WafVerdict::STATUS_SUSPICIOUS, $verdict->status);
        self::assertSame(40, $verdict->score);
    }

    public function testSoftFindingsReachTheBlockThreshold(): void
    {
        $config = new Config(['waf' => ['thresholds' => ['block' => 50, 'suspicious' => 20]]]);
        $waf = new Waf($config, [
            self::stubRule('first', self::finding('first', 30, false)),
            self::stubRule('second', self::finding('second', 20, false)),
        ]);

        $verdict = $waf->inspect(new WafRequest());

        self::assertTrue($verdict->blocked);
        self::assertSame(50, $verdict->score);
    }

    public function testScoreIsCappedAtOneHundred(): void
    {
        $waf = new Waf(new Config(), [
            self::stubRule('a', self::finding('a', 60, false)),
            self::stubRule('b', self::finding('b', 60, false)),
            self::stubRule('c', self::finding('c', 60, false)),
        ]);

        $verdict = $waf->inspect(new WafRequest());

        self::assertSame(100, $verdict->score);
        self::assertTrue($verdict->blocked);
    }

    public function testThrowingRuleIsSkippedAndLogged(): void
    {
        $logger = new class implements LoggerInterface {
            /** @var list<string> */
            public array $messages = [];

            public function log(string $level, string $message, array $context = []): void
            {
                $this->messages[] = $level . ': ' . $message;
            }

            public function error(string $message, array $context = []): void
            {
                $this->log('error', $message, $context);
            }

            public function warning(string $message, array $context = []): void
            {
                $this->log('warning', $message, $context);
            }

            public function info(string $message, array $context = []): void
            {
                $this->log('info', $message, $context);
            }

            public function debug(string $message, array $context = []): void
            {
                $this->log('debug', $message, $context);
            }
        };

        $waf = new Waf(new Config(), [
            self::throwingRule('broken'),
            self::stubRule('xss', self::finding('xss', 90, true)),
        ], $logger);

        $verdict = $waf->inspect(new WafRequest());

        self::assertTrue($verdict->blocked);
        self::assertCount(1, $verdict->findings);
        self::assertCount(1, $logger->messages);
        self::assertStringContainsString('failing open', $logger->messages[0]);
    }

    public function testAllRulesDisabledProduceACleanVerdict(): void
    {
        $config = new Config([
            'waf' => [
                'rules' => [
                    'sql_injection' => false,
                    'xss' => false,
                    'path_traversal' => false,
                    'command_injection' => false,
                    'scanner' => false,
                    'header_injection' => false,
                    'protocol' => false,
                    'ip_reputation' => false,
                    'rate_limit' => false,
                ],
            ],
        ]);

        $verdict = Waf::withDefaultRules($config)->inspect(new WafRequest(
            method: 'GET',
            uri: '/.env',
            headers: ['host' => 'shop.example'],
        ));

        self::assertTrue($verdict->isClean());
        self::assertSame([], $verdict->findings);
    }

    public function testBuiltInRulesRunThroughTheDefaultSet(): void
    {
        $verdict = Waf::withDefaultRules(new Config(['waf' => ['enabled' => true]]))->inspect(new WafRequest(
            method: 'GET',
            uri: '/.env',
            headers: ['host' => 'shop.example', 'user-agent' => WafTestCase::UA],
        ));

        self::assertTrue($verdict->blocked);
        self::assertSame(['scanner'], $verdict->ruleNames());
    }

    private static function stubRule(string $name, ?WafFinding $finding): RuleInterface
    {
        return new class ($name, $finding) implements RuleInterface {
            public function __construct(
                private readonly string $ruleName,
                private readonly ?WafFinding $ruleFinding,
            ) {}

            public function name(): string
            {
                return $this->ruleName;
            }

            public function inspect(WafRequest $request): ?WafFinding
            {
                return $this->ruleFinding;
            }
        };
    }

    private static function throwingRule(string $name): RuleInterface
    {
        return new class ($name) implements RuleInterface {
            public function __construct(private readonly string $ruleName) {}

            public function name(): string
            {
                return $this->ruleName;
            }

            public function inspect(WafRequest $request): ?WafFinding
            {
                throw new RuntimeException('rule failure');
            }
        };
    }

    private static function finding(string $rule, int $severity, bool $hard): WafFinding
    {
        return new WafFinding($rule, $severity, $hard, 'test finding', [], 'test');
    }
}
