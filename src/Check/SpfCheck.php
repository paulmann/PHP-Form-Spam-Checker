<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Dns\ResolverInterface;
use FormSpamChecker\Support\EmailAddress;
use FormSpamChecker\Support\SpfEvaluator;
use FormSpamChecker\Support\SpfResult;

/**
 * Domain-level SPF trust signal for the e-mail domain claimed in a form field.
 *
 * This is deliberately *not* "is the form submitter an authorised sender": a
 * visitor's IP is not the sending MTA, so `fail`/`softfail` for a legitimate
 * `gmail.com` address would be normal. The question this check answers is
 * "does the claimed domain publish a usable SPF policy":
 *
 * - no `v=spf1` record, several records, or a policy the evaluator rejects
 *   (`permerror`): `HAM` with `spf.missing_score` ("suspicious");
 * - a policy that is present and syntactically usable: `HAM` with score 0;
 *   `pass`/`fail`/`softfail`/`neutral` describe the visitor's address, not the
 *   domain, and are recorded as evidence only;
 * - a temporary DNS failure only (unreachable with the shipped resolvers):
 *   `UNCERTAIN`, no score;
 * - no usable e-mail address in the configured fields: `UNCERTAIN`;
 * - without a usable client address the evaluator cannot parse the policy, so
 *   only record presence is judged (`v=spf1` exists exactly once).
 *
 * Passing `SPAM` is never justified by a domain policy alone, so the check only
 * ever contributes a score.
 */
final readonly class SpfCheck implements SpamCheckInterface
{
    public function __construct(
        private ResolverInterface $dns,
        private Config $config,
    ) {}

    public function name(): string
    {
        return 'spf';
    }

    public function check(RequestData $data): CheckOutcome
    {
        $check = $this->name();

        if (!$this->config->bool('spf.enabled', false)) {
            return CheckOutcome::ham($check, 'disabled');
        }

        $domains = EmailAddress::domainsForFields($data, $this->config->array('spf.fields', []));
        if ($domains === []) {
            return CheckOutcome::uncertain($check, 'no usable e-mail address in the configured fields');
        }

        $uniqueDomains = array_values(array_unique($domains));

        $evaluator = new SpfEvaluator(
            $this->dns,
            $this->config->int('spf.lookup_limit', SpfEvaluator::DEFAULT_LOOKUP_LIMIT),
        );
        $missingScore = max(0, $this->config->int('spf.missing_score', 10));

        if (filter_var($data->ip, FILTER_VALIDATE_IP) === false) {
            return $this->checkRecordPresence($check, $uniqueDomains, $evaluator, $missingScore);
        }

        $evidence = [];
        $reasons = [];
        $score = 0;
        $temporary = 0;

        foreach ($uniqueDomains as $domain) {
            $evaluation = $evaluator->evaluate($domain, $data->ip);
            $evidence[$domain] = [
                'result' => $evaluation->result->value,
                'reason' => $evaluation->reason,
                'lookups' => $evaluation->lookups,
                'record' => $evaluation->record,
            ];

            if ($evaluation->result === SpfResult::TEMPERROR) {
                $temporary++;
                continue;
            }

            if (!$evaluation->isNone() && !$evaluation->isPermError()) {
                continue;
            }

            $score += $missingScore;
            $reasons[] = \sprintf('SPF %s for "%s": %s', $evaluation->result->value, $domain, $evaluation->reason);
        }

        if ($score === 0) {
            if ($temporary > 0 && $temporary === \count($uniqueDomains)) {
                return CheckOutcome::uncertain(
                    $check,
                    'SPF lookup failed for every claimed domain (temporary DNS error)',
                    $evidence,
                );
            }

            return new CheckOutcome(
                $check,
                CheckStatus::HAM,
                0,
                'every claimed e-mail domain publishes an SPF policy',
                $evidence,
            );
        }

        return CheckOutcome::suspicious($check, min(100, $score), implode('; ', array_unique($reasons)), $evidence);
    }

    /**
     * Record-presence fallback used when the request has no usable client IP.
     *
     * @param list<string> $domains
     */
    private function checkRecordPresence(
        string $check,
        array $domains,
        SpfEvaluator $evaluator,
        int $missingScore,
    ): CheckOutcome {
        $evidence = [];
        $reasons = [];
        $score = 0;

        foreach ($domains as $domain) {
            $records = $evaluator->spfRecords($domain);
            $count = \count($records);

            $evidence[$domain] = [
                'result' => $count === 1 ? 'record-present' : ($count > 1 ? 'multiple-records' : 'missing'),
                'lookups' => 0,
                'record' => implode(' | ', $records),
            ];

            if ($count === 1) {
                continue;
            }

            $score += $missingScore;
            $reasons[] = $count > 1
                ? \sprintf('multiple SPF records for "%s"', $domain)
                : \sprintf('no SPF record for "%s"', $domain);
        }

        if ($score === 0) {
            return new CheckOutcome(
                $check,
                CheckStatus::HAM,
                0,
                'every claimed e-mail domain publishes an SPF policy',
                $evidence,
            );
        }

        return CheckOutcome::suspicious($check, min(100, $score), implode('; ', array_unique($reasons)), $evidence);
    }
}
