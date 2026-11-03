<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Directory traversal and local file inclusion probes.
 *
 * Traversal sequences (`../`, `..\`, `....//`) are dangerous wherever they
 * appear, including form fields. File-probe signatures (`/etc/passwd`,
 * `php://filter`) are only applied to the request line, because a technician
 * may legitimately mention such a path in a message; an HTTP request carrying
 * it is a probe.
 *
 * The pattern match runs over the URL-decoded variants of the input, which is
 * how encoded and double-encoded payloads (`..%2f`, `%252e%252e%252f`) are
 * caught without a separate pattern per encoding.
 */
final class PathTraversalRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 85;

    protected const bool DEFAULT_HARD = true;

    /** @var list<string> */
    private const array TRAVERSAL_PATTERNS = [
        '/(?:^|[\/\\\\])\.\.(?:[\/\\\\]|$)/',
        '/\.{3,}[\/\\\\]/',
    ];

    /** @var list<string> */
    private const array PROBE_PATTERNS = [
        '/(?:^|[\/\\\\])(?:etc|proc|sys|dev|var\/log)\/(?:passwd|shadow|hosts|group|environ|cmdline|self)\b/i',
        '/\bwin\.ini\b/i',
        '/\b(?:php|file|phar|zip|data):\/\//i',
        '/\b(?:boot|system)\.ini\b/i',
    ];

    public function name(): string
    {
        return 'path_traversal';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $traversal = $this->patternList('patterns', self::TRAVERSAL_PATTERNS);
        $probes = $this->patternList('probe_patterns', self::PROBE_PATTERNS);

        foreach ($this->requestValues($request) as $location => $text) {
            if ($this->isAllowlisted($text)) {
                continue;
            }

            $hit = $this->firstMatch($traversal, $text);
            if ($hit !== null) {
                return $this->finding('Path-traversal sequence detected', $location, $hit);
            }

            if ($this->isRequestLine($location) && $probes !== []) {
                $hit = $this->firstMatch($probes, $text);
                if ($hit !== null) {
                    return $this->finding('Local file inclusion probe detected', $location, $hit);
                }
            }
        }

        return null;
    }

    private function isRequestLine(string $location): bool
    {
        return $location === 'uri' || str_starts_with($location, 'query.');
    }
}
