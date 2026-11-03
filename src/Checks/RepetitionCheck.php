<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;

/**
 * Repetition heuristics: keyboard mashing ("aaaaaaaaaaaaaaaa"), repeated
 * phrases and duplicated words are typical of automated payloads and of
 * low-effort spam.
 */
final class RepetitionCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'repetition';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('repetition.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $text = $submission->text($this->config->excludedFields());

        if ($text === '') {
            return CheckResult::clean($this->name(), 'no text to scan');
        }

        $hits = 0;
        $evidence = [];

        $minRun = max(3, $this->config->int('repetition.min_run', 12));
        $runPattern = '/(\S)\1{' . ($minRun - 1) . ',}/u';

        $runs = preg_match_all($runPattern, $text, $matches);
        if ($runs !== false && $runs > 0) {
            $hits += $runs;
            $evidence['runs'] = array_slice($matches[0], 0, 5);
        }

        $minRepeats = max(2, $this->config->int('repetition.min_word_repeats', 4));
        $words = preg_split('/\s+/u', mb_strtolower($text), -1, PREG_SPLIT_NO_EMPTY);
        $words = $words === false ? [] : $words;

        $frequencies = array_count_values($words);
        foreach ($frequencies as $word => $count) {
            if ($count >= $minRepeats && mb_strlen((string) $word) > 2) {
                $hits++;
                $evidence['repeated_words'][(string) $word] = $count;
            }
        }

        if ($hits === 0) {
            return CheckResult::clean($this->name());
        }

        return CheckResult::suspicious(
            $this->name(),
            min($this->config->int('repetition.max_score', 60), $hits * max(1, $this->config->int('repetition.score', 25))),
            sprintf('%d repetition pattern(s)', $hits),
            $evidence,
        );
    }
}
