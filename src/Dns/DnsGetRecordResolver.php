<?php

declare(strict_types=1);

namespace FormSpamChecker\Dns;

/**
 * Resolver backed by PHP's DNS functions.
 *
 * DNS failures degrade to empty results: a broken resolver must never block a
 * form (checks interpret the empty answer as UNCERTAIN or as a scored signal
 * according to their configuration).
 */
final readonly class DnsGetRecordResolver implements ResolverInterface
{
    /**
     * @return list<string>
     */
    public function txt(string $name): array
    {
        $records = @dns_get_record($name, DNS_TXT);

        if (!is_array($records)) {
            return [];
        }

        $values = [];
        foreach ($records as $record) {
            if (!is_array($record)) {
                continue;
            }

            if (isset($record['entries']) && is_array($record['entries'])) {
                $parts = [];
                foreach ($record['entries'] as $part) {
                    if (is_string($part)) {
                        $parts[] = $part;
                    }
                }
                $values[] = implode('', $parts);
                continue;
            }

            if (isset($record['txt']) && is_string($record['txt'])) {
                $values[] = $record['txt'];
            }
        }

        return $values;
    }

    /**
     * @return list<string>
     */
    public function a(string $name): array
    {
        $records = @dns_get_record($name, DNS_A);

        if (!is_array($records)) {
            return [];
        }

        $values = [];
        foreach ($records as $record) {
            if (is_array($record) && isset($record['ip']) && is_string($record['ip'])) {
                $values[] = $record['ip'];
            }
        }

        return $values;
    }

    /**
     * @return list<string>
     */
    public function mx(string $name): array
    {
        $records = @dns_get_record($name, DNS_MX);

        if (!is_array($records)) {
            return [];
        }

        $values = [];
        foreach ($records as $record) {
            if (is_array($record) && isset($record['target']) && is_string($record['target'])) {
                $values[] = strtolower(rtrim($record['target'], '.'));
            }
        }

        return $values;
    }
}
