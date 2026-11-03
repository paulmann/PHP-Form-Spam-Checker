<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Support\Patterns;
use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Cross-site-scripting signatures in the URI, query, fields, cookies and body.
 *
 * A `<script>` tag or a `javascript:` URI in a request parameter is an attack,
 * not a message, so the default finding is hard. Entity-encoded variants are
 * not scanned by default: they occur in legitimate HTML-heavy correspondence
 * and belong to the (non-blocking) form checks.
 */
final class XssRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 90;

    protected const bool DEFAULT_HARD = true;

    public function name(): string
    {
        return 'xss';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $patterns = $this->patternList('patterns', Patterns::xssStrongPatterns());

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

            return $this->finding('XSS signature detected', $location, $hit);
        }

        return null;
    }
}
