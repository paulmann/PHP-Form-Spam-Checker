<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * One form submission: the submitted fields, the request context and the
 * identifier of the form they belong to.
 *
 * The class never mutates the fields. Helpers return normalised copies so that
 * checks can work with strings without trusting the original types.
 */
final class Submission
{
    /**
     * @param array<string, mixed> $fields
     */
    public function __construct(
        public readonly array $fields,
        public readonly Context $context,
        public readonly string $formId = 'default',
    ) {
    }

    public function has(string $field): bool
    {
        return array_key_exists($field, $this->fields);
    }

    /**
     * Scalar field value as a trimmed string; arrays and objects become ''.
     */
    public function value(string $field): string
    {
        if (!array_key_exists($field, $this->fields)) {
            return '';
        }

        $value = $this->fields[$field];

        if (is_string($value)) {
            return trim($value);
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        if (is_bool($value)) {
            return $value ? '1' : '';
        }

        return '';
    }

    /**
     * Field values as strings, skipping the excluded field names.
     *
     * @param list<string> $exclude
     * @return array<string, string>
     */
    public function content(array $exclude = []): array
    {
        $flip = array_fill_keys($exclude, true);
        $result = [];

        foreach ($this->fields as $name => $value) {
            if (isset($flip[$name])) {
                continue;
            }

            if (is_string($value)) {
                $trimmed = trim($value);
                if ($trimmed !== '') {
                    $result[$name] = $trimmed;
                }
                continue;
            }

            if (is_int($value) || is_float($value)) {
                $result[$name] = (string) $value;
            }
        }

        return $result;
    }

    /**
     * All content joined with a newline, for pattern-oriented checks.
     *
     * @param list<string> $exclude
     */
    public function text(array $exclude = []): string
    {
        return implode("\n", $this->content($exclude));
    }

    /**
     * Best-effort value of a field sent under one of several names.
     *
     * @param list<string> $fields
     */
    public function first(array $fields): string
    {
        foreach ($fields as $field) {
            $value = $this->value($field);
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * Truncated, single-line representation of the fields for logs.
     *
     * @param list<string> $exclude
     * @return array<string, string>
     */
    public function sample(array $exclude = [], int $limit = 120): array
    {
        $sample = [];
        foreach ($this->content($exclude) as $name => $value) {
            $single = preg_replace('/\s+/u', ' ', $value) ?? $value;
            $sample[$name] = mb_substr($single, 0, $limit);
        }

        return $sample;
    }
}
