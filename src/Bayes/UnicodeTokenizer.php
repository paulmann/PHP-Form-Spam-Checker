<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

use InvalidArgumentException;

/**
 * Deterministic Unicode tokeniser for the Bayesian classifier.
 *
 * - the text is lower-cased with `mb_strtolower()` (UTF-8);
 * - tokens are split on anything that is not a letter or a decimal digit, so
 *   punctuation, markup and emoji disappear and no language is privileged;
 * - words shorter than `$minLength` (default 2) are dropped as noise;
 * - consecutive kept words produce bigrams ("buy now"), which carry much of the
 *   signal in short spam messages;
 * - the per-document word count and the per-token count are capped, so one
 *   pathological submission cannot dominate the model or the score.
 *
 * Every branch is bounded and depends only on the input string and the
 * constructor options, which keeps training and scoring reproducible.
 */
final readonly class UnicodeTokenizer implements TokenizerInterface
{
    public function __construct(
        private int $minLength = 2,
        private bool $bigrams = true,
        private int $maxWordsPerDocument = 2000,
        private int $maxCountPerToken = 5,
        private int $maxTextLength = 20000,
    ) {
        if ($this->minLength < 1) {
            throw new InvalidArgumentException('The minimum token length must be at least 1.');
        }

        if ($this->maxWordsPerDocument < 1) {
            throw new InvalidArgumentException('The document word cap must be at least 1.');
        }

        if ($this->maxCountPerToken < 1) {
            throw new InvalidArgumentException('The per-token count cap must be at least 1.');
        }

        if ($this->maxTextLength < 1) {
            throw new InvalidArgumentException('The text length cap must be at least 1.');
        }
    }

    public function tokenize(string $text): array
    {
        $text = trim($text);

        if ($text === '') {
            return [];
        }

        if (mb_strlen($text, 'UTF-8') > $this->maxTextLength) {
            $text = mb_substr($text, 0, $this->maxTextLength, 'UTF-8');
        }

        $parts = preg_split('/[^\p{L}\p{Nd}]+/u', mb_strtolower($text, 'UTF-8'), -1, PREG_SPLIT_NO_EMPTY);

        if (!\is_array($parts)) {
            // Malformed UTF-8: refuse to guess, an empty bag scores as neutral.
            return [];
        }

        $words = [];
        foreach ($parts as $part) {
            if (mb_strlen($part, 'UTF-8') < $this->minLength) {
                continue;
            }

            $words[] = $part;

            if (\count($words) >= $this->maxWordsPerDocument) {
                break;
            }
        }

        if ($words === []) {
            return [];
        }

        $counts = [];
        foreach ($words as $word) {
            $counts[$word] = min($this->maxCountPerToken, ($counts[$word] ?? 0) + 1);
        }

        if ($this->bigrams) {
            $last = \count($words) - 1;

            for ($index = 0; $index < $last; $index++) {
                $bigram = $words[$index] . ' ' . $words[$index + 1];
                $counts[$bigram] = min($this->maxCountPerToken, ($counts[$bigram] ?? 0) + 1);
            }
        }

        // Stable key order makes the tokeniser output comparison-friendly.
        ksort($counts);

        return $counts;
    }
}
