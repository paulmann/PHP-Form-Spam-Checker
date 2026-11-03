<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Behavioral\Honeypot;
use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Token\FormToken;
use PHPUnit\Framework\TestCase;

final class FormProtectorV2Test extends TestCase
{
    private function protector(Config $config): FormProtector
    {
        return new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);
    }

    public function testStaticHoneypotIsRenderedByDefault(): void
    {
        $html = $this->protector(new Config(['storage' => ['driver' => 'memory']]))->fields('contact');

        self::assertStringContainsString('name="website"', $html);
        self::assertStringContainsString('aria-hidden="true"', $html);
        self::assertStringNotContainsString('_fs_ts', $html);
    }

    public function testHoneypotCanBeDisabled(): void
    {
        $html = $this->protector(new Config())->fields('contact', ['honeypot' => false]);

        self::assertStringNotContainsString('website', $html);
    }

    public function testTimeTrapTokenIsRenderedAndValid(): void
    {
        $secret = '0123456789abcdef-secret';
        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'time_trap' => ['enabled' => true, 'secret' => $secret],
        ]);

        $html = $this->protector($config)->fields('contact');

        self::assertMatchesRegularExpression('/name="_fs_ts" value="([^"]+)"/', $html);
        preg_match('/name="_fs_ts" value="([^"]+)"/', $html, $matches);
        self::assertIsInt((new FormToken($secret))->verify($matches[1], 'contact'));
    }

    public function testDynamicHoneypotWhenConfigured(): void
    {
        if (!class_exists(Honeypot::class)) {
            self::markTestSkipped('behavioral module not present in this checkout');
        }

        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'behavioral' => ['honeypot' => ['dynamic' => true, 'secret' => '0123456789abcdef-secret']],
        ]);

        $html = $this->protector($config)->fields('contact');
        $expected = (new Honeypot($config))->fieldName('contact');

        self::assertStringContainsString('name="' . $expected . '"', $html);
    }

    public function testVerifyRequestUsesSuperglobals(): void
    {
        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'user_agent' => ['allow_empty' => true],
        ]);
        $protector = $this->protector($config);

        $previousPost = $_POST;
        $previousServer = $_SERVER;
        $_POST = ['name' => 'bot', 'website' => 'filled'];
        $_SERVER = ['REMOTE_ADDR' => '203.0.113.50'];

        try {
            $verdict = $protector->verifyRequest('contact');
        } finally {
            $_POST = $previousPost;
            $_SERVER = $previousServer;
        }

        self::assertTrue($verdict->isSpam());
    }

    public function testVerifyAcceptsExplicitContext(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory']]);

        $verdict = $this->protector($config)->verify(
            ['name' => 'Иван', 'email' => 'ivan@example.ru'],
            'contact',
            new Context('203.0.113.51', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0'),
        );

        self::assertTrue($verdict->isClean());
    }
}
