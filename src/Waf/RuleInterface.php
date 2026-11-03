<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

/**
 * One HTTP firewall rule.
 *
 * A rule inspects the whole request and returns its strongest finding, or null
 * when the request looks legitimate. Rules must be stateless per request:
 * counters and caches belong in injected collaborators (StorageInterface).
 */
interface RuleInterface
{
    /**
     * Stable machine name used in configuration (`waf.rules.<name>`) and logs.
     */
    public function name(): string;

    public function inspect(WafRequest $request): ?WafFinding;
}
