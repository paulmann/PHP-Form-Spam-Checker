<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Optional IP-reputation signal for the WAF.
 *
 * Reputation is not a property of a request body: the rule hands the injected
 * check a {@see RequestData} that carries the client IP and nothing else, so a
 * network check (AbuseIPDB, DNSBL) cannot accidentally inspect or log form
 * content. A check that returns ERROR or UNCERTAIN contributes nothing, which
 * is the usual fail-open contract.
 *
 * The rule is disabled by default and stays silent when no collaborator was
 * injected, so the WAF never performs network I/O unless the application
 * explicitly wires a check.
 */
final class IpReputationRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 100;

    protected const bool DEFAULT_HARD = true;

    public function __construct(
        Config $config,
        private readonly ?SpamCheckInterface $check = null,
    ) {
        parent::__construct($config);
    }

    public function name(): string
    {
        return 'ip_reputation';
    }

    protected function defaultEnabled(): bool
    {
        return false;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $check = $this->check;

        if ($check === null) {
            return null;
        }

        $ip = trim($request->ip);

        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $outcome = $check->check($this->requestDataForIp($request, $ip));

        if ($outcome->status === CheckStatus::ERROR || $outcome->status === CheckStatus::UNCERTAIN) {
            return null;
        }

        if ($outcome->status !== CheckStatus::SPAM && $outcome->score <= 0) {
            return null;
        }

        $threshold = max(0, min(100, $this->intOption('threshold', 90)));
        $score = max(1, min(100, $outcome->score));
        $hard = $outcome->status === CheckStatus::SPAM && $score >= $threshold;

        return $this->finding(
            $outcome->status === CheckStatus::SPAM
                ? 'client IP reputation is abusive'
                : 'client IP reputation is suspicious',
            'ip',
            [
                'check' => $check->name(),
                'status' => $outcome->status->value,
                'score' => $score,
                'threshold' => $threshold,
                'reason' => $outcome->reason,
            ],
            $score,
            $hard,
        );
    }

    private function requestDataForIp(WafRequest $request, string $ip): RequestData
    {
        return new RequestData(
            fields: [],
            ip: $ip,
            headers: [],
            cookies: [],
            query: [],
            method: $request->method,
            uri: '',
            body: '',
            now: $request->timestamp(),
            formId: $request->formId,
        );
    }

    private function intOption(string $key, int $default): int
    {
        $value = $this->option($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
