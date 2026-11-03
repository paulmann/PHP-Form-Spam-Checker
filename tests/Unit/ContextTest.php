<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Context;
use FormSpamChecker\Submission;
use PHPUnit\Framework\TestCase;

final class ContextTest extends TestCase
{
    private array $serverBackup = [];

    protected function setUp(): void
    {
        $this->serverBackup = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
        parent::tearDown();
    }

    public function testFromGlobalsReadsRequestValues(): void
    {
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.7',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/141.0',
            'HTTP_REFERER' => 'https://example.ru/contacts/',
            'REQUEST_URI' => '/api/lead',
        ];

        $context = Context::fromGlobals();

        self::assertSame('203.0.113.7', $context->ip);
        self::assertSame('Mozilla/5.0 (X11; Linux x86_64) Firefox/141.0', $context->userAgent);
        self::assertSame('https://example.ru/contacts/', $context->referer);
        self::assertSame('/api/lead', $context->page);
    }

    public function testForwardedForIsTrustedOnlyFromLoopbackProxy(): void
    {
        $_SERVER = [
            'REMOTE_ADDR' => '198.51.100.4',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9, 198.51.100.4',
        ];

        self::assertSame('198.51.100.4', Context::fromGlobals()->ip);

        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        self::assertSame('203.0.113.9', Context::fromGlobals()->ip);
    }

    public function testCloudflareHeaderWinsOverRemoteAddress(): void
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_CF_CONNECTING_IP' => '203.0.113.11',
        ];

        self::assertSame('203.0.113.11', Context::fromGlobals()->ip);
    }

    public function testFromArraySupportsAliasesAndNow(): void
    {
        $context = Context::fromArray([
            'ip' => '203.0.113.5',
            'ua' => 'TestUA/1.0',
            'page' => '/register/',
            'now' => 1700000000,
        ]);

        self::assertSame('203.0.113.5', $context->ip);
        self::assertSame('TestUA/1.0', $context->userAgent);
        self::assertSame('/register/', $context->page);
        self::assertSame(1700000000, $context->timestamp());
    }

    public function testTimestampUsesCurrentTimeByDefault(): void
    {
        $before = time();
        $now = (new Context())->timestamp();

        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual($before + 5, $now);
    }

    public function testToArrayRoundTrip(): void
    {
        $context = new Context('203.0.113.1', 'UA', 'https://ref', '/page', 1700000000);
        $restored = Context::fromArray($context->toArray());

        self::assertSame($context->ip, $restored->ip);
        self::assertSame($context->userAgent, $restored->userAgent);
        self::assertSame($context->timestamp(), $restored->timestamp());
    }

    public function testSubmissionHelpersNormaliseValues(): void
    {
        $submission = new Submission(
            [
                'name' => '  Иван  ',
                'count' => 42,
                'flag' => true,
                'nested' => ['a' => 'b'],
                'website' => '',
                'empty' => '   ',
            ],
            new Context(),
            'contact',
        );

        self::assertTrue($submission->has('name'));
        self::assertFalse($submission->has('missing'));
        self::assertSame('Иван', $submission->value('name'));
        self::assertSame('42', $submission->value('count'));
        self::assertSame('1', $submission->value('flag'));
        self::assertSame('', $submission->value('nested'));
        self::assertSame('', $submission->value('missing'));
        self::assertSame('Иван', $submission->first(['missing', 'name']));
        self::assertSame('', $submission->first(['missing']));
    }

    public function testContentAndSampleRespectExclusions(): void
    {
        $submission = new Submission(
            [
                'name' => 'Иван',
                'message' => "Первая строка\nВторая",
                'website' => 'spam',
                'empty' => '',
            ],
            new Context(),
            'contact',
        );

        $content = $submission->content(['website']);

        self::assertSame(['name' => 'Иван', 'message' => "Первая строка\nВторая"], $content);
        self::assertStringContainsString('Иван', $submission->text(['website']));
        self::assertArrayNotHasKey('website', $submission->content(['website']));

        $sample = $submission->sample([], 5);
        self::assertSame('Иван', $sample['name']);
        self::assertStringNotContainsString("\n", $sample['message']);
    }
}
