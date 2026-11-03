<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Config;
use FormSpamChecker\Dns\ResolverInterface;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Storage\MemoryStorage;
use PHPUnit\Framework\TestCase;

/**
 * Verifies that optional network checks are wired into the pipeline only when
 * enabled, and that a missing API key / empty resolver never reaches the network
 * or blocks a submission.
 */
final class RemoteWiringTest extends TestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    public function testNetworkChecksAreWiredOnlyWhenEnabled(): void
    {
        $resolver = new class implements ResolverInterface {
            /** @return list<string> */
            public function txt(string $name): array
            {
                return [];
            }

            /** @return list<string> */
            public function a(string $name): array
            {
                return [];
            }

            /** @return list<string> */
            public function mx(string $name): array
            {
                return [];
            }
        };

        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'cache' => ['driver' => 'memory'],
            'abuseipdb' => ['enabled' => true],
            'dnsbl' => ['enabled' => true],
            'spf' => ['enabled' => true],
            'dmarc' => ['enabled' => false],
        ]);

        $checker = new SpamChecker($config, new MemoryStorage(), null, null, null, null, $resolver);
        $request = new \FormSpamChecker\Data\RequestData(
            ['name' => 'Иван', 'email' => 'ivan@example.com'],
            '203.0.113.10',
            ['user-agent' => self::UA],
            [],
            [],
            'POST',
            '/form',
            '',
            1_700_000_000,
            'contact',
        );

        $verdict = $checker->checkRequest($request);
        $names = array_map(static fn($outcome): string => $outcome->check, $verdict->outcomes);

        self::assertContains('abuseipdb', $names);
        self::assertContains('dnsbl', $names);
        self::assertContains('spf', $names);
        self::assertNotContains('dmarc', $names);
        self::assertTrue($verdict->isClean(), 'No API key and an empty resolver must not block');

        $plain = new SpamChecker(new Config(['storage' => ['driver' => 'memory']]), new MemoryStorage());
        $plainNames = array_map(
            static fn($outcome): string => $outcome->check,
            $plain->checkRequest($request)->outcomes,
        );

        self::assertNotContains('abuseipdb', $plainNames);
        self::assertNotContains('dnsbl', $plainNames);
    }
}
