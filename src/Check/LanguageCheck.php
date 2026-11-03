<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * Script analysis.
 *
 * Two independent signals, both off by default:
 *
 *  1. mixed-script detection ("Пpивет" mixes Cyrillic and Latin letters to
 *     evade keyword filters) — point-based;
 *  2. optional requirement that name fields contain Cyrillic (`require_cyrillic`
 *     + `fields`): a submission whose name/surname is Latin-only is suspicious
 *     (or spam, depending on `missing_score` vs the verdict thresholds).
 *
 * Only configured name-like fields are examined for the Cyrillic requirement;
 * e-mail addresses, company names and free-text messages are never punished for
 * being Latin.
 */
final readonly class LanguageCheck implements SpamCheckInterface
{
    /**
     * Default name-like fields (normalised: lower-case, separators removed).
     *
     * @var list<string>
     */
    private const array DEFAULT_NAME_FIELDS = [
        'name', 'fio', 'fullname', 'full_name', 'firstname', 'first_name',
        'lastname', 'last_name', 'surname', 'secondname', 'second_name',
        'middlename', 'middle_name', 'family', 'givenname', 'given_name',
        'имя', 'фамилия', 'фио',
    ];

    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'language';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('language.enabled', false)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $score = 0;
        $reasons = [];
        $evidence = [];

        $text = $data->text($this->config->excludedFields());

        if ($text !== '') {
            $words = preg_split('/[^\p{L}]+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
            $mixed = [];

            foreach ($words === false ? [] : $words as $word) {
                $hasCyrillic = preg_match('/\p{Cyrillic}/u', $word) === 1;
                $hasLatin = preg_match('/[A-Za-z]/', $word) === 1;

                if ($hasCyrillic && $hasLatin) {
                    $mixed[] = $word;
                }
            }

            if ($mixed !== []) {
                $score += min(
                    $this->config->int('language.max_score', 40),
                    \count($mixed) * max(1, $this->config->int('language.mixed_script_score', 20)),
                );
                $reasons[] = \sprintf('%d word(s) mix Cyrillic and Latin letters', \count($mixed));
                $evidence['mixed_words'] = \array_slice($mixed, 0, 10);
            }
        }

        if ($this->config->bool('language.require_cyrillic', false)) {
            $missing = $this->nameFieldsWithoutCyrillic($data);

            if ($missing !== []) {
                $score += \count($missing) * max(1, $this->config->int('language.missing_score', 40));
                $reasons[] = \sprintf('%d name field(s) contain no Cyrillic letters', \count($missing));
                $evidence['fields_without_cyrillic'] = $missing;
            }
        }

        if ($score === 0) {
            return CheckOutcome::ham($this->name());
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(
                max(1, $this->config->int('language.max_score', 40)),
                $score,
            ),
            implode('; ', $reasons),
            $evidence,
        );
    }

    /**
     * Configured name fields that contain enough letters and none of them
     * Cyrillic. Field names are compared ignoring case and separators, so
     * `first_name`, `firstName` and `FirstName` all match.
     *
     * @return list<string>
     */
    private function nameFieldsWithoutCyrillic(RequestData $data): array
    {
        $configured = $this->config->array('language.fields', []);
        $wanted = [];

        foreach ($configured === [] ? self::DEFAULT_NAME_FIELDS : $configured as $field) {
            if (\is_string($field) && $field !== '') {
                $wanted[$this->normaliseField($field)] = true;
            }
        }

        $minLetters = max(1, $this->config->int('language.min_letters', 2));
        $missing = [];

        foreach ($data->fields as $field => $value) {
            if (!\is_string($value)) {
                continue;
            }

            if (!isset($wanted[$this->normaliseField($field)])) {
                continue;
            }

            $value = trim($value);

            if ($value === '') {
                continue;
            }

            $letters = preg_match_all('/\p{L}/u', $value);

            if ($letters === false || $letters < $minLetters) {
                continue;
            }

            if (preg_match('/\p{Cyrillic}/u', $value) !== 1) {
                $missing[] = $field;
            }
        }

        return $missing;
    }

    private function normaliseField(string $field): string
    {
        return strtolower((string) preg_replace('/[^A-Za-zА-Яа-я0-9]+/u', '', $field));
    }
}
