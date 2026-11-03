<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Support\Patterns;
use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * SQL-injection signatures in the URI, query, fields, cookies and text body.
 *
 * Only high-precision signatures are used by default: this rule runs before
 * the request reaches the application, so a phrase from ordinary prose such as
 * "select the report from the list" must never match. The weaker heuristics of
 * {@see \FormSpamChecker\Checks\SqlInjectionCheck} are intentionally absent;
 * a site that wants them can add them through
 * `waf.rules.sql_injection.extra_patterns`.
 */
final class SqlInjectionRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 90;

    protected const bool DEFAULT_HARD = true;

    public function name(): string
    {
        return 'sql_injection';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $patterns = $this->patternList('patterns', Patterns::sqlStrongPatterns());

        if ($patterns === []) {
            return null;
        }

        foreach ($this->requestValues($request) as $location => $text) {
            if ($this->isAllowlisted($text)) {
                continue;
            }

            $hit = $this->firstMatch($patterns, $text);
            if ($hit === null) {
                continue;
            }

            return $this->finding('SQL-injection signature detected', $location, $hit);
        }

        return null;
    }
}
