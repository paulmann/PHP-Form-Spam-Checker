<?php

declare(strict_types=1);

namespace FormSpamChecker\Token;

use FormSpamChecker\Exception\InvalidConfigException;
use JsonException;

/**
 * Signed, URL-safe token that records *when* a form was rendered.
 *
 * The signature (HMAC-SHA-256) prevents a bot from inventing a timestamp: it
 * must have received a real token from the server. The token is bound to a
 * form id so that a token issued for one form cannot be replayed on another.
 *
 * The token is not a session and carries no personal data: form id, issue
 * time and 8 random bytes. Format:
 *
 *     base64url(json{"f":"form","t":1699999999,"n":"hex"}) . "." . base64url(hmac)
 */
final class FormToken
{
    private const VERSION = 1;

    public function __construct(private readonly string $secret)
    {
        if (mb_strlen($secret) < 16) {
            throw new InvalidConfigException('Token secret must be at least 16 characters long.');
        }
    }

    public function issue(string $formId, ?int $now = null): string
    {
        $payload = json_encode([
            'v' => self::VERSION,
            'f' => $formId,
            't' => $now ?? time(),
            'n' => bin2hex(random_bytes(8)),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $encoded = self::base64UrlEncode($payload);

        return $encoded . '.' . self::base64UrlEncode($this->sign($encoded));
    }

    /**
     * Verify signature, form binding and payload shape.
     *
     * Returns the issue timestamp, or null when the token is not ours.
     */
    public function verify(string $token, string $formId): ?int
    {
        $parts = explode('.', $token);

        if (\count($parts) !== 2) {
            return null;
        }

        [$encoded, $signature] = $parts;

        if ($encoded === '' || $signature === '') {
            return null;
        }

        $expected = self::base64UrlEncode($this->sign($encoded));

        if (!hash_equals($expected, $signature)) {
            return null;
        }

        $payload = self::base64UrlDecode($encoded);
        if ($payload === null) {
            return null;
        }

        try {
            $data = json_decode($payload, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!\is_array($data) || ($data['v'] ?? null) !== self::VERSION) {
            return null;
        }

        if (!\is_string($data['f'] ?? null) || !\is_int($data['t'] ?? null)) {
            return null;
        }

        if (!hash_equals($formId, $data['f'])) {
            return null;
        }

        return $data['t'];
    }

    private function sign(string $encodedPayload): string
    {
        return hash_hmac('sha256', $encodedPayload, $this->secret, true);
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): ?string
    {
        $padded = strtr($value, '-_', '+/');
        $padded .= str_repeat('=', (4 - \strlen($padded) % 4) % 4);

        $decoded = base64_decode($padded, true);

        return $decoded === false ? null : $decoded;
    }
}
