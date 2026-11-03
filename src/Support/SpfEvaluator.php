<?php

declare(strict_types=1);

namespace FormSpamChecker\Support;

use FormSpamChecker\Dns\ResolverInterface;

/**
 * RFC 7208 subset SPF evaluator, testable against a fake resolver.
 *
 * Supported: `v=spf1` TXT discovery, qualifiers `+ - ~ ?`, the mechanisms
 * `all`, `ip4`, `ip6`, `a`, `mx` (with IPv4 CIDR suffixes) and `include`, the
 * `redirect=` modifier, `exp=`/unknown modifiers (ignored per RFC 7208 §6), the
 * "more than one v=spf1 record is a permerror" rule (§4.5) and the lookup limit
 * of §4.6.4 (default 10; `a`, `mx`, `include`, `redirect` and each MX host A
 * lookup count towards it).
 *
 * Documented limitations (deliberate, not silent):
 *
 * - macros (`%{d}`, `%{ir}`, ...) are not expanded, so a macro-bearing term is a
 *   syntax error rather than a guess;
 * - `ptr` and `exists` are not implemented and yield `permerror`;
 * - `a`/`mx` match IPv4 only, because `ResolverInterface` exposes `A` records
 *   (no `AAAA`); an IPv6 client address simply does not match those mechanisms;
 * - the "void lookup" limit (§4.6.4, max 2 empty answers) is not enforced;
 * - the resolver abstraction cannot report a DNS failure, so `temperror` is
 *   never produced by the shipped resolvers.
 */
final readonly class SpfEvaluator
{
    public const int DEFAULT_LOOKUP_LIMIT = 10;

    /**
     * Hard cap on include/redirect nesting: a recursive SPF graph must never
     * exhaust the PHP stack, and a cycle has to degrade to `permerror`.
     */
    private const int MAX_DEPTH = 20;

    public function __construct(
        private ResolverInterface $dns,
        private int $lookupLimit = self::DEFAULT_LOOKUP_LIMIT,
    ) {}

    /**
     * Evaluate the SPF policy of `$domain` for the client address `$ip`.
     */
    public function evaluate(string $domain, string $ip): SpfEvaluation
    {
        $domain = $this->normalizeDomain($domain);

        if ($domain === '') {
            return new SpfEvaluation('', SpfResult::NONE, 'no domain to evaluate');
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return new SpfEvaluation($domain, SpfResult::NONE, 'no client IP address to evaluate against');
        }

        $lookups = 0;

        return $this->evaluateDomain($domain, $ip, $lookups, 0);
    }

    /**
     * Published `v=spf1` records for a domain; two or more records are a
     * permerror per RFC 7208 §4.5.
     *
     * @return list<string>
     */
    public function spfRecords(string $domain): array
    {
        // SPF targets routinely contain underscores (`_spf.google.com`), which
        // are legal in DNS names but not in host names.
        $domain = $this->normalizeTarget($domain);
        if ($domain === '') {
            return [];
        }

        $records = [];

        foreach ($this->dns->txt($domain) as $txt) {
            $value = trim($txt);

            if ($value === '') {
                continue;
            }

            if (preg_match('/^v=spf1(?:\s|$)/i', $value) === 1) {
                $records[] = $value;
            }
        }

        return $records;
    }

    /**
     * @param int $lookups shared DNS-query counter for the whole evaluation
     */
    private function evaluateDomain(string $domain, string $ip, int &$lookups, int $depth): SpfEvaluation
    {
        if ($depth > self::MAX_DEPTH) {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, 'include/redirect nesting is too deep (possible loop)', $lookups);
        }

        $records = $this->spfRecords($domain);

        if (\count($records) > 1) {
            return new SpfEvaluation(
                $domain,
                SpfResult::PERMERROR,
                'multiple v=spf1 records published',
                $lookups,
                implode(' | ', $records),
            );
        }

        if ($records === []) {
            return new SpfEvaluation($domain, SpfResult::NONE, 'no v=spf1 record published', $lookups);
        }

        $record = $records[0];
        $terms = preg_split('/\s+/', $record);
        if ($terms === false) {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, 'record cannot be tokenised', $lookups, $record);
        }

        $mechanisms = [];
        $redirect = null;

        foreach (\array_slice($terms, 1) as $term) {
            if ($term === '') {
                continue;
            }

            $modifier = $this->parseModifier($term);
            if ($modifier !== null) {
                if ($modifier[0] === 'redirect') {
                    $redirect = $modifier[1];
                }

                // exp= and unknown modifiers are ignored (RFC 7208 §6).
                continue;
            }

            $mechanisms[] = $term;
        }

        foreach ($mechanisms as $term) {
            $outcome = $this->evaluateMechanism($term, $domain, $ip, $lookups, $depth);
            if ($outcome !== null) {
                return new SpfEvaluation($domain, $outcome->result, $outcome->reason, $lookups, $record);
            }
        }

        if ($redirect !== null && $redirect !== '') {
            $target = $this->normalizeTarget($redirect);
            if ($target === '') {
                return new SpfEvaluation($domain, SpfResult::PERMERROR, 'redirect= target is not a valid domain', $lookups, $record);
            }

            $lookups++;
            if ($this->limitExceeded($lookups)) {
                return $this->lookupLimitError($domain, $lookups, $record);
            }

            $result = $this->evaluateDomain($target, $ip, $lookups, $depth + 1);

            if ($result->isNone()) {
                return new SpfEvaluation(
                    $domain,
                    SpfResult::PERMERROR,
                    'redirect target "' . $target . '" publishes no v=spf1 record',
                    $lookups,
                    $record,
                );
            }

            return $result;
        }

        return new SpfEvaluation($domain, SpfResult::NEUTRAL, 'no mechanism matched', $lookups, $record);
    }

    /**
     * @param  int                $lookups shared DNS-query counter
     * @return SpfEvaluation|null null when the mechanism does not match
     */
    private function evaluateMechanism(string $term, string $domain, string $ip, int &$lookups, int $depth): ?SpfEvaluation
    {
        $qualifier = '+';
        $rest = $term;
        $first = $term[0];

        if ($first === '+' || $first === '-' || $first === '~' || $first === '?') {
            $qualifier = $first;
            $rest = substr($term, 1);
        }

        $colon = strpos($rest, ':');
        $head = $colon === false ? $rest : substr($rest, 0, $colon);
        $argument = $colon === false ? '' : substr($rest, $colon + 1);

        $slash = strpos($head, '/');
        $name = strtolower($slash === false ? $head : substr($head, 0, $slash));
        $headCidr = $slash === false ? null : substr($head, $slash + 1);

        return match ($name) {
            'all' => $this->qualify($qualifier, $domain, 'all', $lookups),
            'ip4' => $this->evaluateIpMechanism('ip4', $qualifier, $argument, $domain, $ip, $lookups),
            'ip6' => $this->evaluateIpMechanism('ip6', $qualifier, $argument, $domain, $ip, $lookups),
            'a', 'mx' => $this->evaluateHostMechanism($name, $qualifier, $argument, $headCidr, $domain, $ip, $lookups),
            'include' => $this->evaluateInclude($qualifier, $argument, $domain, $ip, $lookups, $depth),
            default => new SpfEvaluation(
                $domain,
                SpfResult::PERMERROR,
                \sprintf('unsupported or unknown mechanism "%s"', $name),
                $lookups,
            ),
        };
    }

    /**
     * @param int $lookups shared DNS-query counter
     */
    private function evaluateIpMechanism(
        string $family,
        string $qualifier,
        string $argument,
        string $domain,
        string $ip,
        int &$lookups,
    ): ?SpfEvaluation {
        $argument = trim($argument);

        if ($argument === '') {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, $family . ' mechanism without an address', $lookups);
        }

        $parts = explode('/', $argument, 2);
        $network = trim($parts[0]);
        $expectedLength = $family === 'ip4' ? 4 : 16;

        $packed = inet_pton($network);
        if ($packed === false || \strlen($packed) !== $expectedLength) {
            return new SpfEvaluation(
                $domain,
                SpfResult::PERMERROR,
                \sprintf('%s mechanism has an invalid address "%s"', $family, $network),
                $lookups,
            );
        }

        if (isset($parts[1]) && !ctype_digit(trim($parts[1]))) {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, $family . ' mechanism has an invalid prefix length', $lookups);
        }

        if (!$this->matchesCidr($ip, $argument, $family === 'ip4' ? 32 : 128)) {
            return null;
        }

        return $this->qualify($qualifier, $domain, $family . ':' . $argument, $lookups);
    }

    /**
     * `a` and `mx` mechanisms: resolve host address(es) and match the client.
     *
     * @param  int                $lookups shared DNS-query counter
     * @return SpfEvaluation|null null when the mechanism does not match
     */
    private function evaluateHostMechanism(
        string $mechanism,
        string $qualifier,
        string $argument,
        ?string $headCidr,
        string $domain,
        string $ip,
        int &$lookups,
    ): ?SpfEvaluation {
        $target = $domain;
        $cidr = \is_string($headCidr) && $headCidr !== '' ? $headCidr : null;

        if ($argument !== '') {
            $slash = strpos($argument, '/');
            if ($slash === false) {
                $target = trim($argument);
            } else {
                $target = trim(substr($argument, 0, $slash));
                $cidr = substr($argument, $slash + 1);
            }
        }

        $target = $this->normalizeTarget($target);
        if ($target === '') {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, $mechanism . ' mechanism without a valid domain', $lookups);
        }

        $packedClient = inet_pton($ip);
        $clientIsIpv4 = $packedClient !== false && \strlen($packedClient) === 4;

        // ResolverInterface exposes A records only: an IPv6 client cannot match
        // these mechanisms, and no query is spent on a match that cannot happen.
        if (!$clientIsIpv4) {
            return null;
        }

        $lookups++;
        if ($this->limitExceeded($lookups)) {
            return $this->lookupLimitError($domain, $lookups, '');
        }

        $suffix = \is_string($cidr) && ctype_digit($cidr) ? '/' . $cidr : '';

        if ($mechanism === 'a') {
            return $this->matchRecords($this->dns->a($target), $qualifier, $ip, $suffix, $domain, 'a:' . $target, $lookups);
        }

        foreach ($this->dns->mx($target) as $host) {
            $lookups++;
            if ($this->limitExceeded($lookups)) {
                return $this->lookupLimitError($domain, $lookups, '');
            }

            $matched = $this->matchRecords(
                $this->dns->a($host),
                $qualifier,
                $ip,
                $suffix,
                $domain,
                'mx:' . $target,
                $lookups,
            );

            if ($matched !== null) {
                return $matched;
            }
        }

        return null;
    }

    /**
     * @param list<string> $records
     * @param int          $lookups shared DNS-query counter
     */
    private function matchRecords(
        array $records,
        string $qualifier,
        string $ip,
        string $suffix,
        string $domain,
        string $label,
        int $lookups,
    ): ?SpfEvaluation {
        foreach ($records as $record) {
            if ($this->matchesCidr($ip, $record . $suffix, 32)) {
                return $this->qualify($qualifier, $domain, $label, $lookups);
            }
        }

        return null;
    }

    /**
     * @param  int                $lookups shared DNS-query counter
     * @return SpfEvaluation|null null when the include does not match
     */
    private function evaluateInclude(
        string $qualifier,
        string $argument,
        string $domain,
        string $ip,
        int &$lookups,
        int $depth,
    ): ?SpfEvaluation {
        $target = $this->normalizeTarget($argument);

        if ($target === '') {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, 'include: mechanism without a valid domain', $lookups);
        }

        $lookups++;
        if ($this->limitExceeded($lookups)) {
            return $this->lookupLimitError($domain, $lookups, '');
        }

        $result = $this->evaluateDomain($target, $ip, $lookups, $depth + 1);

        if ($result->isPermError() || $result->isTempError()) {
            return new SpfEvaluation(
                $domain,
                $result->result,
                \sprintf('include "%s": %s', $target, $result->reason),
                $lookups,
            );
        }

        if ($result->isNone()) {
            return new SpfEvaluation($domain, SpfResult::PERMERROR, \sprintf('include target "%s" publishes no v=spf1 record', $target), $lookups);
        }

        if ($result->isPass()) {
            return $this->qualify($qualifier, $domain, 'include:' . $target, $lookups);
        }

        return null;
    }

    private function qualify(string $qualifier, string $domain, string $mechanism, int $lookups): SpfEvaluation
    {
        [$result, $label] = match ($qualifier) {
            '-' => [SpfResult::FAIL, 'fail'],
            '~' => [SpfResult::SOFTFAIL, 'softfail'],
            '?' => [SpfResult::NEUTRAL, 'neutral'],
            default => [SpfResult::PASS, 'pass'],
        };

        return new SpfEvaluation($domain, $result, \sprintf('%s matched (%s)', $mechanism, $label), $lookups);
    }

    private function lookupLimitError(string $domain, int $lookups, string $record): SpfEvaluation
    {
        return new SpfEvaluation(
            $domain,
            SpfResult::PERMERROR,
            \sprintf('SPF lookup limit of %d DNS-querying terms exceeded', $this->effectiveLookupLimit()),
            $lookups,
            $record,
        );
    }

    private function limitExceeded(int $lookups): bool
    {
        return $lookups > $this->effectiveLookupLimit();
    }

    private function effectiveLookupLimit(): int
    {
        return $this->lookupLimit > 0 ? $this->lookupLimit : self::DEFAULT_LOOKUP_LIMIT;
    }

    /**
     * @return array{0: string, 1: string}|null [name, value] for `name=value` terms
     */
    private function parseModifier(string $term): ?array
    {
        if (preg_match('/^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$/', $term, $matches) !== 1) {
            return null;
        }

        return [strtolower($matches[1]), trim($matches[2])];
    }

    /**
     * IPv4/IPv6 CIDR match; the client and the network must be the same family.
     */
    private function matchesCidr(string $ip, string $spec, int $defaultPrefix): bool
    {
        $parts = explode('/', $spec, 2);
        $network = trim($parts[0]);
        $prefix = $defaultPrefix;

        if (isset($parts[1])) {
            $prefixPart = trim($parts[1]);
            if (!ctype_digit($prefixPart)) {
                return false;
            }
            $prefix = (int) $prefixPart;
        }

        $packedIp = inet_pton($ip);
        $packedNetwork = inet_pton($network);

        if ($packedIp === false || $packedNetwork === false || \strlen($packedIp) !== \strlen($packedNetwork)) {
            return false;
        }

        $bits = \strlen($packedIp) * 8;
        if ($prefix < 0 || $prefix > $bits) {
            return false;
        }

        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;

        if ($fullBytes > 0 && substr($packedIp, 0, $fullBytes) !== substr($packedNetwork, 0, $fullBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;

        return (\ord($packedIp[$fullBytes]) & $mask) === (\ord($packedNetwork[$fullBytes]) & $mask);
    }

    /**
     * A claimed e-mail domain: must be a valid hostname.
     */
    private function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain, " \t\n\r\0\x0B."));

        if ($domain === '' || \strlen($domain) > 253) {
            return '';
        }

        if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            return '';
        }

        return $domain;
    }

    /**
     * An SPF reference target (`include:`, `redirect=`, `a:`, `mx:`).
     *
     * Underscores are invalid in host names but legal and common in SPF targets
     * (`_spf.google.com`), so this validator is intentionally laxer than
     * `normalizeDomain()`.
     */
    private function normalizeTarget(string $name): string
    {
        $name = strtolower(trim($name, " \t\n\r\0\x0B."));

        if ($name === '' || \strlen($name) > 253) {
            return '';
        }

        if (preg_match('/^[a-z0-9_][a-z0-9_.-]*$/', $name) !== 1) {
            return '';
        }

        return $name;
    }
}
