<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\FormProtector;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Token\FormToken;
use PHPUnit\Framework\TestCase;

final class FormProtectorTest extends TestCase
{
    public function testHoneypotFieldIsRenderedByDefault(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory']]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $html = $protector->fields('contact');

        self::assertStringContainsString('name="website"', $html);
        self::assertStringContainsString('aria-hidden="true"', $html);
        self::assertStringNotContainsString('_fs_ts', $html);
    }

    public function testHoneypotCanBeDisabledPerRendering(): void
    {
        $config = new Config();
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $html = $protector->fields('contact', ['honeypot' => false]);

        self::assertStringNotContainsString('website', $html);
    }

    public function testTokenIsRenderedWhenTimeTrapIsEnabled(): void
    {
        $config = new Config([
            'time_trap' => ['enabled' => true, 'secret' => '0123456789abcdef-secret'],
        ]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $html = $protector->fields('contact');

        self::assertMatchesRegularExpression('/name="_fs_ts" value="([^"]+)"/', $html);
        preg_match('/name="_fs_ts" value="([^"]+)"/', $html, $matches);

        $issuedAt = (new FormToken('0123456789abcdef-secret'))->verify($matches[1], 'contact');
        self::assertIsInt($issuedAt);
    }

    public function testVerifyRequestUsesPostSuperglobal(): void
    {
        $config = new Config([
            'storage' => ['driver' => 'memory'],
            'user_agent' => ['allow_empty' => true],
        ]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $previous = $_SERVER;
        $_POST = ['name' => 'bot', 'website' => 'filled'];
        $_SERVER = ['REMOTE_ADDR' => '203.0.113.50'];

        try {
            $verdict = $protector->verifyRequest('contact');
        } finally {
            $_POST = [];
            $_SERVER = $previous;
        }

        self::assertTrue($verdict->isSpam());
    }

    public function testVerifyAcceptsExplicitContext(): void
    {
        $config = new Config(['storage' => ['driver' => 'memory']]);
        $protector = new FormProtector(new SpamChecker($config, new MemoryStorage()), $config);

        $verdict = $protector->verify(
            ['name' => 'Иван', 'email' => 'ivan@example.ru'],
            'contact',
            new Context('203.0.113.51', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0'),
        );

        self::assertTrue($verdict->isClean());
    }
}
