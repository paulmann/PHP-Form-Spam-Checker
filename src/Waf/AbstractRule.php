<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf;

use FormSpamChecker\Config;

/**
 * Shared behaviour of the built-in rules: the enable switch, configurable
 * severity/hardness, pattern lists and the text sources a content rule scans.
 *
 * The configuration key of a rule is `waf.rules.<name>`. It accepts either a
 * plain boolean (`true`/`false`) or an array with the keys `enabled`,
 * `severity`, `hard`, `patterns`, `extra_patterns`, `allowlist` — so a site can
 * tune one rule without a new class.
 */
abstract class AbstractRule implements RuleInterface
{
    protected const int DEFAULT_SEVERITY = 80;

    protected const bool DEFAULT_HARD = true;

    public function __construct(
        protected readonly Config $config,
    ) {
    }

    /**
     * Inspect the request unless the rule is disabled.
     */
    final public function inspect(WafRequest $request): ?WafFinding
    {
        if (!$this->enabled()) {
            return null;
        }

        return $this->check($request);
    }

    /**
     * Rule-specific inspection; called only when the rule is enabled.
     */
    abstract protected function check(WafRequest $request): ?WafFinding;

    /**
     * Default of `waf.rules.<name>` when the configuration does not set it.
     */
    abstract protected function defaultEnabled(): bool;

    /**
     * Is this rule enabled for the current configuration?
     */
    final public function enabled(): bool
    {
        $raw = $this->config->get('waf.rules.' . $this->name());

        if (is_array($raw)) {
            if (!array_key_exists('enabled', $raw)) {
                return $this->defaultEnabled();
            }

            $flag = filter_var($raw['enabled'], FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);

            return $flag ?? $this->defaultEnabled();
        }

        return $this->config->bool('waf.rules.' . $this->name(), $this->defaultEnabled());
    }

    /**
     * Effective severity (0..100): rule default with an optional config override.
     */
    final protected function severity(): int
    {
        $value = $this->option('severity', static::DEFAULT_SEVERITY);

        return is_numeric($value) ? max(0, min(100, (int) $value)) : static::DEFAULT_SEVERITY;
    }

    /**
     * Effective hardness: a hard finding blocks the request on its own.
     */
    final protected function hard(): bool
    {
        $value = $this->option('hard', static::DEFAULT_HARD);

        if (is_bool($value)) {
            return $value;
        }

        return filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE) ?? static::DEFAULT_HARD;
    }

    /**
     * Build a finding from the rule's identity and configured defaults.
     *
     * @param array<string, mixed> $evidence
     */
    final protected function finding(
        string $reason,
        string $location,
        array $evidence = [],
        ?int $severity = null,
        ?bool $hard = null,
    ): WafFinding {
        return new WafFinding(
            rule: $this->name(),
            severity: $severity ?? $this->severity(),
            hard: $hard ?? $this->hard(),
            reason: $reason,
            evidence: $evidence,
            location: $location,
        );
    }

    /**
     * Read one key of the rule's configuration array; $default when absent.
     */
    final protected function option(string $key, mixed $default): mixed
    {
        $raw = $this->config->get('waf.rules.' . $this->name());

        if (is_array($raw) && array_key_exists($key, $raw)) {
            return $raw[$key];
        }

        return $default;
    }

    /**
     * @param list<string> $default
     * @return list<string>
     */
    final protected function patternList(string $key, array $default): array
    {
        $configured = $this->option($key, null);
        $patterns = is_array($configured) ? self::strings($configured) : $default;

        $extra = $this->option('extra_' . $key, null);
        if (is_array($extra)) {
            $patterns = [...$patterns, ...self::strings($extra)];
        }

        return $patterns;
    }

    /**
     * A list-of-strings setting: array when configured, $default otherwise.
     *
     * @param list<string> $default
     * @return list<string>
     */
    final protected function listOption(string $key, array $default): array
    {
        $configured = $this->option($key, null);

        return is_array($configured) ? self::strings($configured) : $default;
    }

    /**
     * True when the configured allowlist matches the text, so it is not scanned.
     */
    final protected function isAllowlisted(string $text): bool
    {
        foreach (['allowlist', 'allow_patterns'] as $key) {
            $patterns = $this->option($key, null);

            if (!is_array($patterns)) {
                continue;
            }

            foreach (self::strings($patterns) as $pattern) {
                if (@preg_match($pattern, $text) === 1) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Text sources a content rule scans, keyed by location.
     *
     * The body is included only when it is textual: a multipart upload or a
     * binary payload is not prose and must not be pattern-matched. Header
     * values are scanned by dedicated rules, not here, to avoid treating a
     * legitimate Accept-Language list as an attack.
     *
     * @return array<string, string>
     */
    final protected function requestValues(WafRequest $request, bool $includeUri = true): array
    {
        $values = [];

        if ($includeUri) {
            $values['uri'] = $request->uri;
        }

        foreach ($request->query as $name => $value) {
            $this->flattenInto($values, 'query.' . $name, $value);
        }

        foreach ($request->fields as $name => $value) {
            $this->flattenInto($values, 'field.' . $name, $value);
        }

        foreach ($request->cookies as $name => $value) {
            $this->flattenInto($values, 'cookie.' . $name, $value);
        }

        $body = $request->scannableBody();
        if ($body !== '') {
            $values['body'] = $body;
        }

        return $values;
    }

    /**
     * The text plus its URL-decoded variants.
     *
     * A path traversal payload is usually sent encoded (`..%2f`, double
     * encoded `%252e%252e%252f`), so signatures have to see the decoded form.
     *
     * @return list<string>
     */
    final protected function decodedVariants(string $text): array
    {
        $variants = [$text];

        $raw = rawurldecode($text);
        if ($raw !== $text) {
            $variants[] = $raw;
        }

        $plain = urldecode($text);
        if ($plain !== $text && $plain !== $raw) {
            $variants[] = $plain;
        }

        $twice = rawurldecode($raw);
        if ($twice !== $raw && !in_array($twice, $variants, true)) {
            $variants[] = $twice;
        }

        return $variants;
    }

    /**
     * First pattern that matches one of the text's decoded variants.
     *
     * @param list<string> $patterns
     * @return array{pattern: string, match: string}|null
     */
    final protected function firstMatch(array $patterns, string $text): ?array
    {
        if ($text === '') {
            return null;
        }

        foreach ($this->decodedVariants($text) as $variant) {
            foreach ($patterns as $pattern) {
                $result = @preg_match($pattern, $variant, $matches);

                if ($result !== 1) {
                    continue;
                }

                return [
                    'pattern' => $pattern,
                    'match' => mb_substr($matches[0] ?? '', 0, 120),
                ];
            }
        }

        return null;
    }

    /**
     * @param array<string, string> $target
     */
    private function flattenInto(array &$target, string $prefix, mixed $value, int $depth = 0): void
    {
        if ($depth > 8) {
            return;
        }

        if (is_array($value)) {
            foreach ($value as $key => $item) {
                $this->flattenInto($target, $prefix . '[' . (string) $key . ']', $item, $depth + 1);
            }

            return;
        }

        if (is_string($value)) {
            if (trim($value) !== '') {
                $target[$prefix] = $value;
            }

            return;
        }

        if (is_int($value) || is_float($value)) {
            $target[$prefix] = (string) $value;
        }
    }

    /**
     * @param array<mixed> $values
     * @return list<string>
     */
    private static function strings(array $values): array
    {
        $result = [];

        foreach ($values as $value) {
            if (is_string($value) && $value !== '') {
                $result[] = $value;
            }
        }

        return $result;
    }
}
