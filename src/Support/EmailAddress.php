<?php

declare(strict_types=1);

namespace FormSpamChecker\Support;

use FormSpamChecker\Data\RequestData;

/**
 * E-mail address extraction for the domain-level trust checks (SPF, DMARC, DKIM).
 *
 * Field values are untrusted input: a form may send a bare address
 * (`user@example.com`), a display-name form (`Name <user@example.com>`), a
 * `mailto:` URL or plain junk. The helpers never throw: anything that cannot be
 * read as an address becomes an empty string (or is skipped), and the calling
 * check decides what "no usable address" means.
 */
final class EmailAddress
{
    /**
     * Only the static helpers are part of the API.
     */
    private function __construct() {}

    /**
     * Normalise a raw field value to a lower-case address, `''` when invalid.
     *
     * Accepts `user@example.com`, `Name <user@example.com>`,
     * `"Name" <user@example.com>` and `mailto:user@example.com`.
     */
    public static function fromValue(string $value): string
    {
        $candidate = trim($value);

        if ($candidate === '') {
            return '';
        }

        if (str_starts_with(strtolower($candidate), 'mailto:')) {
            $candidate = trim(substr($candidate, 7));
        }

        // "Display Name <address>" — take the last angle-bracket group. A
        // display name itself may contain '@', so the brackets are authoritative.
        $open = strrpos($candidate, '<');
        if ($open !== false) {
            $close = strpos($candidate, '>', $open + 1);
            if ($close !== false) {
                $candidate = trim(substr($candidate, $open + 1, $close - $open - 1));
            }
        }

        if (filter_var($candidate, FILTER_VALIDATE_EMAIL) === false) {
            return '';
        }

        return strtolower($candidate);
    }

    /**
     * Domain part of a normalised address, `''` when the value is not an address.
     */
    public static function domain(string $value): string
    {
        $address = self::fromValue($value);
        if ($address === '') {
            return '';
        }

        $at = strrpos($address, '@');
        if ($at === false) {
            return '';
        }

        $domain = substr($address, $at + 1);
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            return '';
        }

        return $domain;
    }

    /**
     * Map of configured field name to e-mail domain, skipping empty/invalid values.
     *
     * @param  array<mixed>          $fields configured field names (non-string entries are ignored)
     * @return array<string, string>
     */
    public static function domainsForFields(RequestData $data, array $fields): array
    {
        $domains = [];

        foreach ($fields as $field) {
            if (!\is_string($field) || $field === '') {
                continue;
            }

            $domain = self::domain($data->field($field));
            if ($domain !== '') {
                $domains[$field] = $domain;
            }
        }

        return $domains;
    }
}
