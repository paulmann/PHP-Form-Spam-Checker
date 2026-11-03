<?php

declare(strict_types=1);

namespace FormSpamChecker\Behavioral;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use NoDiscard;

/**
 * Dynamic honeypot: the field name is derived from the form id and the current
 * hour, so a static list of "known" honeypot names is useless to a bot.
 *
 * Name derivation:
 *
 *     prefix . substr(HMAC-SHA-256(secret, "formId|hourBucket"), 0, 12)
 *
 * where `hourBucket = intdiv(now, 3600)`. The previous bucket is accepted too,
 * because a form rendered at 12:59 and submitted at 13:00 is legitimate.
 *
 * When the configured secret is shorter than 16 characters the HMAC step is
 * replaced by a plain SHA-256 of the same input: the resulting names are stable
 * and still non-obvious, but they are not bound to a secret. `isConfigured()`
 * reports this state so the check can fail open with a configuration error.
 */
final readonly class Honeypot
{
    public const SECRET_MIN_LENGTH = 16;
    public const BUCKET_SECONDS = 3600;
    public const TOKEN_LENGTH = 12;

    private const DEFAULT_PREFIX = '_hp_';

    public function __construct(private Config $config) {}

    /**
     * Hidden field name for the current hour bucket.
     */
    #[NoDiscard]
    public function fieldName(string $formId, ?int $now = null): string
    {
        return $this->fieldNameForBucket($formId, $this->bucket($now ?? time()));
    }

    /**
     * Field names accepted right now: the current bucket and the previous one.
     *
     * @return list<string>
     */
    public function candidates(string $formId, ?int $now = null): array
    {
        $bucket = $this->bucket($now ?? time());

        return [
            $this->fieldNameForBucket($formId, $bucket),
            $this->fieldNameForBucket($formId, $bucket - 1),
        ];
    }

    /**
     * Inspect a submission: return the name of the filled honeypot field, or
     * null when no honeypot field carries a value.
     *
     * The time comes from the request snapshot (`RequestData::timestamp()`), so
     * callers can inject a deterministic clock.
     */
    public function verify(RequestData $data, string $formId): ?string
    {
        foreach ($this->candidates($formId, $data->timestamp()) as $name) {
            if ($data->hasField($name) && $data->field($name) !== '') {
                return $name;
            }
        }

        foreach ($this->staticFields() as $name) {
            if ($data->hasField($name) && $data->field($name) !== '') {
                return $name;
            }
        }

        return null;
    }

    /**
     * Configured static honeypot names, used when the dynamic mode is off.
     *
     * `behavioral.honeypot.static` is the 2.0 key; `honeypot.fields` is the
     * 1.x static list and stays supported for existing configurations.
     *
     * @return list<string>
     */
    public function staticFields(): array
    {
        $fields = [];
        $configured = $this->config->array('behavioral.honeypot.static', []);

        if ($configured === []) {
            $configured = $this->config->array('honeypot.fields', []);
        }

        foreach ($configured as $field) {
            if (\is_string($field) && $field !== '') {
                $fields[] = $field;
            }
        }

        return array_values(array_unique($fields));
    }

    public function prefix(): string
    {
        $prefix = $this->config->string('behavioral.honeypot.field_prefix', self::DEFAULT_PREFIX);

        return $prefix !== '' ? $prefix : self::DEFAULT_PREFIX;
    }

    public function secret(): string
    {
        return $this->config->string('behavioral.honeypot.secret');
    }

    /**
     * Whether the dynamic derivation is bound to a proper secret.
     */
    public function isConfigured(): bool
    {
        return mb_strlen($this->secret(), 'UTF-8') >= self::SECRET_MIN_LENGTH;
    }

    public function bucket(int $now): int
    {
        return intdiv($now, self::BUCKET_SECONDS);
    }

    private function fieldNameForBucket(string $formId, int $bucket): string
    {
        $material = $formId . '|' . $bucket;
        $secret = $this->secret();

        $token = mb_strlen($secret, 'UTF-8') >= self::SECRET_MIN_LENGTH
            ? substr(hash_hmac('sha256', $material, $secret), 0, self::TOKEN_LENGTH)
            : substr(hash('sha256', 'honeypot|' . $material), 0, self::TOKEN_LENGTH);

        return $this->prefix() . $token;
    }
}
