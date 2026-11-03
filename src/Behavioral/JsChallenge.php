<?php

declare(strict_types=1);

namespace FormSpamChecker\Behavioral;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Exception\InvalidConfigException;
use JsonException;
use NoDiscard;

/**
 * Minimal, dependency-free JavaScript challenge.
 *
 * The server issues a signed token that carries a small numeric challenge:
 *
 *     base64url(json{"v":1,"f":formId,"t":unixTime,"c":challenge,"n":nonce})
 *     . "." . base64url(HMAC-SHA-256(payload))
 *
 * The inline script decodes the challenge from the token (the payload is public,
 * the signature is not), computes the answer `challenge * 7 + 3` and writes it
 * into the hidden answer field. A bot that does not execute JavaScript submits
 * an empty or stale answer and is only ever *suspicious* — this check never
 * returns a hard SPAM verdict, it fails open by design.
 *
 * The script contains no external dependencies and is byte-identical for a
 * given form id, so it can be allow-listed with a CSP hash instead of
 * `'unsafe-inline'`:
 *
 *     $hash = (new JsChallenge($config))->inlineScriptHash($formId);
 *     header("Content-Security-Policy: script-src 'self' " . $hash);
 *
 * The answer is not a secret (the client must compute it); the signature is
 * what prevents a bot from inventing a valid token for another form or time.
 */
final readonly class JsChallenge
{
    public const TOKEN_VERSION = 1;
    public const SECRET_MIN_LENGTH = 16;
    public const DEFAULT_MAX_AGE = 86400;

    private const CLOCK_SKEW_SECONDS = 5;
    private const DEFAULT_FIELD = '_js';

    private string $secret;
    private string $field;
    private int $maxAge;

    public function __construct(private Config $config)
    {
        $secret = $this->config->string('behavioral.js_challenge.secret');
        if ($secret === '') {
            // A shared deployment secret is a reasonable default; the time trap
            // already requires it to be strong.
            $secret = $this->config->string('time_trap.secret');
        }

        $this->secret = $secret;

        $field = $this->config->string('behavioral.js_challenge.field', self::DEFAULT_FIELD);
        $this->field = $field !== '' ? $field : self::DEFAULT_FIELD;
        $this->maxAge = max(1, $this->config->int('behavioral.js_challenge.max_age', self::DEFAULT_MAX_AGE));
    }

    /**
     * Hidden field that receives the computed answer.
     */
    public function field(): string
    {
        return $this->field;
    }

    /**
     * Hidden field that carries the signed token.
     */
    public function tokenField(): string
    {
        return $this->field . '_token';
    }

    /**
     * Why the challenge cannot be used, or null when the secret is strong enough.
     */
    public function configError(): ?string
    {
        if (mb_strlen($this->secret, 'UTF-8') >= self::SECRET_MIN_LENGTH) {
            return null;
        }

        return \sprintf(
            'behavioral.js_challenge.secret (or time_trap.secret) must be at least %d characters.',
            self::SECRET_MIN_LENGTH,
        );
    }

    public function isConfigured(): bool
    {
        return $this->configError() === null;
    }

    /**
     * Issue a signed challenge token for one form.
     *
     * @return array{token: string, challenge: int}
     */
    #[NoDiscard]
    public function issue(string $formId, ?int $now = null): array
    {
        $error = $this->configError();
        if ($error !== null) {
            throw new InvalidConfigException($error);
        }

        $timestamp = $now ?? time();
        $challenge = $this->challengeFor($formId, $timestamp);

        $payload = json_encode([
            'v' => self::TOKEN_VERSION,
            'f' => $formId,
            't' => $timestamp,
            'c' => $challenge,
            'n' => bin2hex(random_bytes(8)),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $encoded = self::base64UrlEncode($payload);

        return [
            'token' => $encoded . '.' . self::base64UrlEncode($this->sign($encoded)),
            'challenge' => $challenge,
        ];
    }

    /**
     * The answer the browser must submit for a challenge.
     *
     * The formula is mirrored verbatim in `inlineScript()`: keep them in sync.
     */
    public function expectedAnswer(int $challenge): string
    {
        return (string) ($challenge * 7 + 3);
    }

    /**
     * Verify the answer field and the signed token of one submission.
     *
     * Fail-open by contract: malformed, expired, forged or missing data simply
     * returns false (the check turns that into a suspicion score, never SPAM).
     */
    public function verify(RequestData $data, string $formId): bool
    {
        if ($this->configError() !== null) {
            return false;
        }

        $answer = $data->field($this->field);
        $token = $data->field($this->tokenField());

        if ($answer === '' || $token === '') {
            return false;
        }

        $payload = $this->decodeToken($token, $formId);
        if ($payload === null) {
            return false;
        }

        $age = $data->timestamp() - $payload['t'];
        if ($age < -self::CLOCK_SKEW_SECONDS || $age > $this->maxAge) {
            return false;
        }

        return hash_equals($this->expectedAnswer($payload['c']), $answer);
    }

    /**
     * Self-contained inline script that fills the answer field.
     *
     * The output is stable for a given form id (no timestamps or random values
     * are embedded), which is what makes the CSP hash reusable. The script body
     * deliberately contains no `%` character either: form renderers routinely
     * embed the markup through `sprintf()`, where a stray percent sign would be
     * read as a format specifier (bitwise padding replaces the usual modulo).
     */
    public function inlineScript(string $formId): string
    {
        return "\n<script>\n" . $this->inlineScriptBody($formId) . "\n</script>";
    }

    /**
     * CSP source value for the inline script, e.g. `sha256-...`.
     *
     * The hash covers the script text exactly as `inlineScript()` emits it,
     * between the `<script>` tags.
     */
    public function inlineScriptHash(string $formId): string
    {
        return 'sha256-' . base64_encode(hash('sha256', $this->inlineScriptBody($formId), true));
    }

    private function inlineScriptBody(string $formId): string
    {
        $replacements = [
            '{{FORM}}' => $this->jsLiteral($formId),
            '{{TOKEN}}' => $this->jsLiteral($this->tokenField()),
        ];

        return strtr(<<<'JS'
            (function () {
              var formId = {{FORM}};
              var tokenField = {{TOKEN}};
              var script = document.currentScript;
              var root = script && script.parentNode && script.parentNode.querySelector
                ? script.parentNode
                : document;
              var answer = root.querySelector('[data-fs-js]') || document.querySelector('[data-fs-js]');
              if (!answer) { return; }
              var box = answer.form || (answer.closest ? answer.closest('form') : null);
              if (!box) { return; }
              var token = box.querySelector('input[name="' + tokenField + '"]')
                || box.querySelector('input[name="' + answer.name + '_token"]');
              if (!token || !token.value) { return; }
              var parts = token.value.split('.');
              if (parts.length !== 2) { return; }
              var b64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
              var pad = (4 - (b64.length & 3)) & 3;
              while (pad > 0) { b64 += '='; pad -= 1; }
              var payload;
              try {
                var bytes = Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
                payload = JSON.parse(new TextDecoder('utf-8').decode(bytes));
              } catch (e) { return; }
              if (!payload || payload.f !== formId || typeof payload.c !== 'number') { return; }
              answer.value = String(payload.c * 7 + 3);
            })();
            JS, $replacements);
    }

    private function challengeFor(string $formId, int $timestamp): int
    {
        $digest = hash_hmac('sha256', 'challenge|' . $formId . '|' . $timestamp, $this->secret);

        return (hexdec(substr($digest, 0, 4)) % 9) + 1;
    }

    /**
     * @return array{v: int, f: string, t: int, c: int}|null
     */
    private function decodeToken(string $token, string $formId): ?array
    {
        $parts = explode('.', $token);

        if (\count($parts) !== 2) {
            return null;
        }

        [$encoded, $signature] = $parts;

        if ($encoded === '' || $signature === '') {
            return null;
        }

        if (!hash_equals(self::base64UrlEncode($this->sign($encoded)), $signature)) {
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

        if (!\is_array($data) || ($data['v'] ?? null) !== self::TOKEN_VERSION) {
            return null;
        }

        if (!\is_string($data['f'] ?? null) || !\is_int($data['t'] ?? null) || !\is_int($data['c'] ?? null)) {
            return null;
        }

        if (!hash_equals($formId, $data['f'])) {
            return null;
        }

        return ['v' => self::TOKEN_VERSION, 'f' => $data['f'], 't' => $data['t'], 'c' => $data['c']];
    }

    private function sign(string $encodedPayload): string
    {
        return hash_hmac('sha256', $encodedPayload, $this->secret, true);
    }

    /**
     * Encode a value as a JavaScript string literal that cannot terminate the
     * surrounding `<script>` element.
     */
    private function jsLiteral(string $value): string
    {
        $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return str_replace('<', '\u003C', $encoded);
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
