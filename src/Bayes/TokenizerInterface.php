<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

/**
 * Splits one document into a bag of tokens with occurrence counts.
 *
 * Implementations must be deterministic: the same text always yields the same
 * map (token => count). A persisted model is only valid while the train-time
 * and score-time tokenisers are identical.
 */
interface TokenizerInterface
{
    /**
     * @return array<string, int> token => occurrence count (always >= 1)
     */
    public function tokenize(string $text): array;
}
