<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Dns\ResolverInterface;

/**
 * DNS blocklist lookup: the client IP is reversed and queried in every
 * configured DNSBL zone.
 *
 * - IPv4: `1.2.3.4` becomes `4.3.2.1.<zone>`; IPv6 is expanded to 32 nibbles
 *   and reversed (RFC 3596 nibble format), which is what dual-stack zones such
 *   as `zen.spamhaus.org` accept for IPv6 lookups;
 * - an answer inside `127.0.0.0/24` is a listing (any other answer, such as
 *   `NXDOMAIN`-turned-empty or a stray `0.0.0.0`, is not);
 * - a listing is a hard `SPAM` with `dnsbl.hit_score`;
 * - a resolver that returns empty answers for every zone yields `HAM`: a broken
 *   resolver must not punish a submission;
 * - zones are queried in configured order and the first hit wins, so one
 *   submission costs at most one DNS round-trip per zone until it is listed.
 *
 * The resolver is expected to be wrapped in `CachedResolver` by the pipeline;
 * this check itself keeps no state.
 */
final readonly class DnsblCheck implements SpamCheckInterface
{
    public function __construct(
        private ResolverInterface $dns,
        private Config $config,
    ) {}

    public function name(): string
    {
        return 'dnsbl';
    }

    public function check(RequestData $data): CheckOutcome
    {
        $check = $this->name();

        if (!$this->config->bool('dnsbl.enabled', false)) {
            return CheckOutcome::ham($check, 'disabled');
        }

        $ip = $data->ip;
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return CheckOutcome::uncertain($check, 'no valid IP address in the request');
        }

        $lookupName = $this->reverseName($ip);
        if ($lookupName === '') {
            return CheckOutcome::uncertain($check, 'cannot build a DNSBL lookup name for the address', ['ip' => $ip]);
        }

        $zones = $this->zones();
        if ($zones === []) {
            return CheckOutcome::uncertain($check, 'no DNSBL zones are configured', ['ip' => $ip]);
        }

        $answers = [];
        $hits = [];

        foreach ($zones as $zone) {
            $query = $lookupName . '.' . $zone;
            $records = $this->dns->a($query);
            $answers[$zone] = $records;

            $listed = [];
            foreach ($records as $record) {
                if ($this->isListingAnswer($record)) {
                    $listed[] = $record;
                }
            }

            if ($listed !== []) {
                $hits[$zone] = $listed;
                break;
            }
        }

        if ($hits !== []) {
            $hitScore = max(1, min(100, $this->config->int('dnsbl.hit_score', 100)));

            return CheckOutcome::spam(
                $check,
                \sprintf('IP %s is listed in DNSBL zone(s): %s', $ip, implode(', ', array_keys($hits))),
                [
                    'ip' => $ip,
                    'lookup_name' => $lookupName,
                    'hits' => $hits,
                    'zones_checked' => array_keys($answers),
                ],
                $hitScore,
            );
        }

        return new CheckOutcome(
            $check,
            CheckStatus::HAM,
            0,
            'IP is not listed in any configured DNSBL zone',
            ['ip' => $ip, 'lookup_name' => $lookupName, 'zones_checked' => array_keys($answers)],
        );
    }

    /**
     * @return list<string>
     */
    private function zones(): array
    {
        $zones = [];

        foreach ($this->config->array('dnsbl.zones', []) as $zone) {
            if (!\is_string($zone)) {
                continue;
            }

            $normalized = strtolower(trim($zone, " \t\n\r\0\x0B."));
            if ($normalized !== '') {
                $zones[] = $normalized;
            }
        }

        return $zones;
    }

    private function reverseName(string $ip): string
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return '';
        }

        if (\strlen($packed) === 4) {
            $octets = explode('.', $ip);

            return implode('.', array_reverse($octets));
        }

        if (\strlen($packed) !== 16) {
            return '';
        }

        $hex = bin2hex($packed);
        $nibbles = str_split($hex);

        return implode('.', array_reverse($nibbles));
    }

    /**
     * A listing is any address inside 127.0.0.0/24 (RFC 5782 §2.1); the last
     * octet carries the zone-specific reason code and is not interpreted here.
     */
    private function isListingAnswer(string $answer): bool
    {
        $packed = inet_pton($answer);
        if ($packed === false || \strlen($packed) !== 4) {
            return false;
        }

        $long = ip2long($answer);

        return $long !== false && ($long & 0xFFFFFF00) === 0x7F000000;
    }
}
