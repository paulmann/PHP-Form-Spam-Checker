<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Log\LoggerInterface;
use FormSpamChecker\Storage\StorageInterface;
use FormSpamChecker\Waf\Rules\CommandInjectionRule;
use FormSpamChecker\Waf\Rules\HeaderInjectionRule;
use FormSpamChecker\Waf\Rules\IpReputationRule;
use FormSpamChecker\Waf\Rules\PathTraversalRule;
use FormSpamChecker\Waf\Rules\ProtocolRule;
use FormSpamChecker\Waf\Rules\RateLimitRule;
use FormSpamChecker\Waf\Rules\ScannerRule;
use FormSpamChecker\Waf\Rules\SqlInjectionRule;
use FormSpamChecker\Waf\Rules\XssRule;
use NoDiscard;
use Throwable;

/**
 * Aggregating HTTP firewall.
 *
 * Runs every rule over one request snapshot and combines the findings:
 * any hard finding blocks; otherwise severities are summed (capped at 100) and
 * compared with `waf.thresholds.block` / `waf.thresholds.suspicious`. The WAF
 * itself is mode-agnostic: answering 403, logging only, or doing nothing is the
 * decision of {@see \FormSpamChecker\Integration\WafGuard}.
 *
 * A rule that throws is reported to the logger and skipped: one broken rule
 * must never turn the firewall into an outage.
 */
final class Waf
{
    /**
     * @param list<RuleInterface> $rules
     */
    public function __construct(
        private readonly Config $config,
        private readonly array $rules,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @return list<RuleInterface>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * Inspect one request and aggregate the rule findings.
     */
    #[NoDiscard]
    public function inspect(WafRequest $request): WafVerdict
    {
        $findings = [];

        foreach ($this->rules as $rule) {
            try {
                $finding = $rule->inspect($request);
            } catch (Throwable $exception) {
                $this->logger?->error(
                    'WAF rule {rule} failed, failing open: {message}',
                    ['rule' => $rule->name(), 'message' => $exception->getMessage()],
                );

                continue;
            }

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        $score = 0;
        $hard = false;

        foreach ($findings as $finding) {
            $score += $finding->severity;

            if ($finding->hard) {
                $hard = true;
            }
        }

        $score = max(0, min(100, $score));

        $blockThreshold = max(1, min(100, $this->config->int('waf.thresholds.block', 60)));
        $suspiciousThreshold = max(1, min($blockThreshold, $this->config->int('waf.thresholds.suspicious', 30)));

        $blocked = $hard || $score >= $blockThreshold;

        $status = match (true) {
            $blocked => WafVerdict::STATUS_BLOCKED,
            $score >= $suspiciousThreshold => WafVerdict::STATUS_SUSPICIOUS,
            default => WafVerdict::STATUS_CLEAN,
        };

        return new WafVerdict($blocked, $score, $findings, $status);
    }

    /**
     * Build the firewall with every built-in rule in a fixed order.
     *
     * Content rules run first (cheap, no I/O), then header/protocol sanity,
     * then the optional collaborators: IP reputation (network) and rate
     * limiting (storage). Without a collaborator the corresponding rule stays
     * silent even when enabled in the configuration.
     */
    public static function withDefaultRules(
        Config $config,
        ?SpamCheckInterface $ipReputation = null,
        ?StorageInterface $rateLimitStorage = null,
        ?LoggerInterface $logger = null,
    ): self {
        return new self($config, [
            new SqlInjectionRule($config),
            new XssRule($config),
            new PathTraversalRule($config),
            new CommandInjectionRule($config),
            new ScannerRule($config),
            new HeaderInjectionRule($config),
            new ProtocolRule($config),
            new IpReputationRule($config, $ipReputation),
            new RateLimitRule($config, $rateLimitStorage),
        ], $logger);
    }
}
