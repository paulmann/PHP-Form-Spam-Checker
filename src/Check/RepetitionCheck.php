<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * Repetition heuristics: keyboard mashing and duplicated words are typical of
 * automated payloads and low-effort spam.
 */
final readonly class RepetitionCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'repetition';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('repetition.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $text = $data->text($this->config->excludedFields());

        if ($text === '') {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        $hits = 0;
        $evidence = [];

        $minRun = max(3, $this->config->int('repetition.min_run', 12));
        $runs = preg_match_all('/(\S)\1{' . ($minRun - 1) . ',}/u', $text, $matches);
        if ($runs !== false && $runs > 0) {
            $hits += $runs;
            $evidence['runs'] = array_slice($matches[0], 0, 5);
        }

        $minRepeats = max(2, $this->config->int('repetition.min_word_repeats', 4));
        $words = preg_split('/\s+/u', mb_strtolower($text), -1, PREG_SPLIT_NO_EMPTY);
        $frequencies = array_count_values($words === false ? [] : $words);

        foreach ($frequencies as $word => $count) {
            if ($count >= $minRepeats && mb_strlen((string) $word) > 2) {
                $hits++;
                $evidence['repeated_words'][(string) $word] = $count;
            }
        }

        if ($hits === 0) {
            return CheckOutcome::ham($this->name());
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(
                $this->config->int('repetition.max_score', 60),
                $hits * max(1, $this->config->int('repetition.score', 25)),
            ),
            sprintf('%d repetition pattern(s)', $hits),
            $evidence,
        );
    }
}
