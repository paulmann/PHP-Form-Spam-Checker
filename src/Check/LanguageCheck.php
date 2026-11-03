<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * Mixed-script (homoglyph) detection: "Пpивет" mixes Cyrillic and Latin letters
 * to evade keyword filters. Point-based and disabled by default.
 */
final readonly class LanguageCheck implements SpamCheckInterface
{
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

        $text = $data->text($this->config->excludedFields());

        if ($text === '') {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        $words = preg_split('/[^\p{L}]+/u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $mixed = [];

        foreach ($words === false ? [] : $words as $word) {
            $hasCyrillic = preg_match('/\p{Cyrillic}/u', $word) === 1;
            $hasLatin = preg_match('/[A-Za-z]/', $word) === 1;

            if ($hasCyrillic && $hasLatin) {
                $mixed[] = $word;
            }
        }

        if ($mixed === []) {
            return CheckOutcome::ham($this->name());
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(
                $this->config->int('language.max_score', 40),
                \count($mixed) * max(1, $this->config->int('language.mixed_script_score', 20)),
            ),
            \sprintf('%d word(s) mix Cyrillic and Latin letters', \count($mixed)),
            ['words' => \array_slice($mixed, 0, 10)],
        );
    }
}
