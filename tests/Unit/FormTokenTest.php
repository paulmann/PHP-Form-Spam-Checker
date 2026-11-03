<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Exception\InvalidConfigException;
use FormSpamChecker\Token\FormToken;
use PHPUnit\Framework\TestCase;

final class FormTokenTest extends TestCase
{
    private const string SECRET = '0123456789abcdef-secret';

    public function testIssueAndVerifyRoundTrip(): void
    {
        $token = new FormToken(self::SECRET);
        $issuedAt = 1_700_000_000;
        $value = $token->issue('contact', $issuedAt);

        self::assertSame($issuedAt, $token->verify($value, 'contact'));
    }

    public function testTokenIsBoundToFormId(): void
    {
        $token = new FormToken(self::SECRET);
        $value = $token->issue('contact');

        self::assertNull($token->verify($value, 'register'));
    }

    public function testTokenIsBoundToSecret(): void
    {
        $value = (new FormToken(self::SECRET))->issue('contact');

        self::assertNull((new FormToken('another-secret-123456'))->verify($value, 'contact'));
    }

    public function testTamperedPayloadIsRejected(): void
    {
        $token = new FormToken(self::SECRET);
        $value = $token->issue('contact');
        [$payload, $signature] = explode('.', $value);

        $decoded = base64_decode(strtr($payload, '-_', '+/'), true);
        self::assertIsString($decoded);
        $data = json_decode($decoded, true);
        $data['t'] += 10;
        $tampered = rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=') . '.' . $signature;

        self::assertNull($token->verify($tampered, 'contact'));
    }

    public function testGarbageIsRejected(): void
    {
        $token = new FormToken(self::SECRET);

        self::assertNull($token->verify('', 'contact'));
        self::assertNull($token->verify('garbage', 'contact'));
        self::assertNull($token->verify('a.b.c', 'contact'));
        self::assertNull($token->verify('a.b', 'contact'));
    }

    public function testShortSecretIsRejected(): void
    {
        $this->expectException(InvalidConfigException::class);
        new FormToken('short');
    }

    public function testTwoTokensDiffer(): void
    {
        $token = new FormToken(self::SECRET);

        self::assertNotSame($token->issue('contact'), $token->issue('contact'));
    }
}
