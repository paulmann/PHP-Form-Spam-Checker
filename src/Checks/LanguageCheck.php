<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;

/**
 * Mixed-script (homoglyph) detection.
 *
 * Attackers copy a Cyrillic word and replace some letters with visually
 * identical Latin ones ("Пpивет"), which survives naive keyword filters.
 * Legitimate names and companies sometimes mix alphabets in one field, so this
 * check is point-based and disabled by default.
 */
final class LanguageCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'language';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('language.enabled', false)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $text = $submission->text($this->config->excludedFields());

        if ($text === '') {
            return CheckResult::clean($this->name(), 'no text to scan');
        }

        $words = preg_split('/[^\p{L}]+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $words = $words === false ? [] : $words;

        $mixed = [];
        foreach ($words as $word) {
            $hasCyrillic = preg_match('/\p{Cyrillic}/u', $word) === 1;
            $hasLatin = preg_match('/[A-Za-z]/', $word) === 1;

            if ($hasCyrillic && $hasLatin) {
                $mixed[] = $word;
            }
        }

        if ($mixed === []) {
            return CheckResult::clean($this->name());
        }

        return CheckResult::suspicious(
            $this->name(),
            min(
                $this->config->int('language.max_score', 40),
                count($mixed) * max(1, $this->config->int('language.mixed_script_score', 20)),
            ),
            sprintf('%d word(s) mix Cyrillic and Latin letters', count($mixed)),
            ['words' => array_slice($mixed, 0, 10)],
        );
    }
}
