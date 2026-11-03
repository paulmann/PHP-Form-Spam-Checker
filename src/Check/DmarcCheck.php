<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Dns\ResolverInterface;
use FormSpamChecker\Support\EmailAddress;

/**
 * Domain-level DMARC trust signal for the e-mail domain claimed in a form field.
 *
 * The check reads `_dmarc.<domain>` (RFC 7489 §6.6.3) and classifies the policy:
 *
 * - enforcing policy (`p=quarantine` or `p=reject`): no score;
 * - weak policy (`p=none`, monitoring only): `dmarc.weak_policy_score`;
 * - missing record, several records, or a record without a valid `p=` tag:
 *   `dmarc.missing_score`;
 * - no usable e-mail address in the configured fields: `UNCERTAIN`.
 *
 * A DMARC policy does not describe the submitting visitor, so this check never
 * returns `SPAM`; it only contributes a score.
 */
final readonly class DmarcCheck implements SpamCheckInterface
{
    public function __construct(
        private ResolverInterface $dns,
        private Config $config,
    ) {}

    public function name(): string
    {
        return 'dmarc';
    }

    public function check(RequestData $data): CheckOutcome
    {
        $check = $this->name();

        if (!$this->config->bool('dmarc.enabled', false)) {
            return CheckOutcome::ham($check, 'disabled');
        }

        $domains = EmailAddress::domainsForFields($data, $this->config->array('dmarc.fields', []));
        if ($domains === []) {
            return CheckOutcome::uncertain($check, 'no usable e-mail address in the configured fields');
        }

        $missingScore = max(0, $this->config->int('dmarc.missing_score', 10));
        $weakScore = max(0, $this->config->int('dmarc.weak_policy_score', 5));

        $score = 0;
        $reasons = [];
        $evidence = [];

        foreach (array_values(array_unique($domains)) as $domain) {
            $inspection = $this->inspectDomain($domain);
            $evidence[$domain] = [
                'result' => $inspection['result'],
                'policy' => $inspection['policy'],
                'record' => $inspection['record'],
            ];

            if ($inspection['result'] === 'ok') {
                continue;
            }

            if ($inspection['result'] === 'weak') {
                $score += $weakScore;
                $reasons[] = \sprintf('weak DMARC policy (p=%s) for "%s"', $inspection['policy'], $domain);
                continue;
            }

            $score += $missingScore;
            $reasons[] = $inspection['result'] === 'missing'
                ? \sprintf('no DMARC record for "%s"', $domain)
                : \sprintf('invalid DMARC record for "%s"', $domain);
        }

        if ($score === 0) {
            return new CheckOutcome(
                $check,
                CheckStatus::HAM,
                0,
                'every claimed e-mail domain publishes an enforcing DMARC policy',
                $evidence,
            );
        }

        return CheckOutcome::suspicious($check, min(100, $score), implode('; ', array_unique($reasons)), $evidence);
    }

    /**
     * @return array{result: 'ok'|'weak'|'missing'|'invalid', policy: string, record: string}
     */
    private function inspectDomain(string $domain): array
    {
        $records = $this->dmarcRecords('_dmarc.' . $domain);

        if (\count($records) > 1) {
            return ['result' => 'invalid', 'policy' => '', 'record' => implode(' | ', $records)];
        }

        if ($records === []) {
            return ['result' => 'missing', 'policy' => '', 'record' => ''];
        }

        $record = $records[0];
        $tags = $this->parseTags($record);
        $policy = strtolower(trim($tags['p'] ?? ''));

        if ($policy !== 'none' && $policy !== 'quarantine' && $policy !== 'reject') {
            return ['result' => 'invalid', 'policy' => $policy, 'record' => $record];
        }

        if ($policy === 'none') {
            return ['result' => 'weak', 'policy' => $policy, 'record' => $record];
        }

        return ['result' => 'ok', 'policy' => $policy, 'record' => $record];
    }

    /**
     * @return list<string>
     */
    private function dmarcRecords(string $name): array
    {
        $records = [];

        foreach ($this->dns->txt($name) as $txt) {
            $value = trim($txt);
            if ($value === '') {
                continue;
            }

            // RFC 7489 §6.6.3: the version tag must be the first tag.
            $firstTag = trim(explode(';', $value, 2)[0]);
            if (preg_match('/^v\s*=\s*dmarc1$/i', $firstTag) === 1) {
                $records[] = $value;
            }
        }

        return $records;
    }

    /**
     * @return array<string, string>
     */
    private function parseTags(string $record): array
    {
        $tags = [];

        foreach (explode(';', $record) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            $equals = strpos($part, '=');
            if ($equals === false) {
                continue;
            }

            $key = strtolower(trim(substr($part, 0, $equals)));
            if ($key === '') {
                continue;
            }

            $tags[$key] = trim(substr($part, $equals + 1));
        }

        return $tags;
    }
}
