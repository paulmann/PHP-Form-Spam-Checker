<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

use InvalidArgumentException;
use NoDiscard;
use Throwable;

/**
 * Multinomial naive Bayes classifier over cached token counts.
 *
 * Train-time and score-time state lives in a `ModelStorageInterface`; the
 * in-memory counts are loaded lazily from it, so a pipeline can construct the
 * classifier once per request without extra wiring.
 *
 * Scoring uses Laplace smoothing (alpha = 1) and the class priors derived from
 * the document counts:
 *
 *     ln odds = ln(prior_spam / prior_ham)
 *         + sum over tokens: count * ln(P(token | spam) / P(token | ham))
 *     P(spam) = 1 / (1 + exp(-ln odds))
 *
 * The probability is clamped to [0.01, 0.99]: one extreme document can never
 * claim absolute certainty. An untrained model (or empty text) returns 0.5.
 */
final class Classifier
{
    private const ALPHA = 1.0;
    private const MIN_PROBABILITY = 0.01;
    private const MAX_PROBABILITY = 0.99;
    private const LOG_ODDS_LIMIT = 50.0;

    /** @var array<string, int> */
    private array $spamTokens = [];

    /** @var array<string, int> */
    private array $hamTokens = [];

    private int $spamDocuments = 0;
    private int $hamDocuments = 0;

    private bool $loaded = false;

    public function __construct(
        private readonly ModelStorageInterface $storage,
        private readonly int $minDocuments = 20,
        private readonly float $threshold = 0.92,
        private readonly TokenizerInterface $tokenizer = new UnicodeTokenizer(),
    ) {
        if ($this->minDocuments < 0) {
            throw new InvalidArgumentException('The minimum document count cannot be negative.');
        }

        if ($this->threshold < 0.0 || $this->threshold > 1.0) {
            throw new InvalidArgumentException('The threshold must be between 0.0 and 1.0.');
        }
    }

    public function tokenizer(): TokenizerInterface
    {
        return $this->tokenizer;
    }

    public function threshold(): float
    {
        return $this->threshold;
    }

    public function minDocuments(): int
    {
        return $this->minDocuments;
    }

    public function storage(): ModelStorageInterface
    {
        return $this->storage;
    }

    /**
     * Add one document to a class.
     *
     * Documents without usable tokens are ignored: they carry no evidence and
     * would only distort the priors.
     */
    public function train(string $text, bool $isSpam): void
    {
        $this->ensureLoaded();

        $tokens = $this->tokenizer->tokenize($text);
        if ($tokens === []) {
            return;
        }

        $counts = &$this->spamTokens;
        if (!$isSpam) {
            $counts = &$this->hamTokens;
        }

        foreach ($tokens as $token => $count) {
            $counts[$token] = ($counts[$token] ?? 0) + $count;
        }

        unset($counts);

        if ($isSpam) {
            $this->spamDocuments++;
        } else {
            $this->hamDocuments++;
        }
    }

    /**
     * CLI-friendly synonym of `train()`, named after the input it receives.
     */
    public function trainFromString(string $text, bool $isSpam): void
    {
        $this->train($text, $isSpam);
    }

    /**
     * Train on many documents at once (CLI trainer path).
     *
     * @param  list<string> $texts
     * @return int          number of documents actually accepted
     */
    public function trainFromList(array $texts, bool $isSpam): int
    {
        $trained = 0;
        foreach ($texts as $text) {
            $before = $this->documentCount();
            $this->train($text, $isSpam);

            if ($this->documentCount() > $before) {
                $trained++;
            }
        }

        return $trained;
    }

    /**
     * Remove one previously trained document (the inverse of `train()`).
     */
    public function untrain(string $text, bool $isSpam): void
    {
        $this->ensureLoaded();

        $tokens = $this->tokenizer->tokenize($text);
        if ($tokens === []) {
            return;
        }

        $counts = &$this->spamTokens;
        if (!$isSpam) {
            $counts = &$this->hamTokens;
        }

        foreach ($tokens as $token => $count) {
            $remaining = ($counts[$token] ?? 0) - $count;

            if ($remaining > 0) {
                $counts[$token] = $remaining;
            } else {
                unset($counts[$token]);
            }
        }

        unset($counts);

        if ($isSpam) {
            $this->spamDocuments = max(0, $this->spamDocuments - 1);
        } else {
            $this->hamDocuments = max(0, $this->hamDocuments - 1);
        }
    }

    /**
     * Spam probability for one document, in [0.01, 0.99], or 0.5 when the
     * model is not trained yet or the text yields no tokens.
     */
    #[NoDiscard]
    public function score(string $text): float
    {
        $this->ensureLoaded();

        $tokens = $this->tokenizer->tokenize($text);
        if ($tokens === []) {
            return 0.5;
        }

        if (!$this->isTrained()) {
            return 0.5;
        }

        $spamTotal = array_sum($this->spamTokens);
        $hamTotal = array_sum($this->hamTokens);

        $vocabulary = [];
        foreach ($this->spamTokens as $token => $count) {
            $vocabulary[$token] = true;
        }
        foreach ($this->hamTokens as $token => $count) {
            $vocabulary[$token] = true;
        }

        $vocabularySize = \count($vocabulary);
        if ($spamTotal === 0 || $hamTotal === 0 || $vocabularySize === 0) {
            return 0.5;
        }

        $spamDenominator = $spamTotal + self::ALPHA * $vocabularySize;
        $hamDenominator = $hamTotal + self::ALPHA * $vocabularySize;

        $priorSpam = ($this->spamDocuments + 1) / ($this->spamDocuments + $this->hamDocuments + 2);
        $logOdds = log($priorSpam / (1.0 - $priorSpam));

        foreach ($tokens as $token => $count) {
            $pSpam = (($this->spamTokens[$token] ?? 0) + self::ALPHA) / $spamDenominator;
            $pHam = (($this->hamTokens[$token] ?? 0) + self::ALPHA) / $hamDenominator;
            $logOdds += $count * log($pSpam / $pHam);
        }

        if ($logOdds >= self::LOG_ODDS_LIMIT) {
            return self::MAX_PROBABILITY;
        }

        if ($logOdds <= -self::LOG_ODDS_LIMIT) {
            return self::MIN_PROBABILITY;
        }

        $probability = 1.0 / (1.0 + exp(-$logOdds));

        return max(self::MIN_PROBABILITY, min(self::MAX_PROBABILITY, $probability));
    }

    /**
     * Whether the model has seen at least `$minDocuments` documents of both
     * classes. Below that threshold the classifier abstains (`score()` = 0.5).
     */
    public function isTrained(): bool
    {
        $this->ensureLoaded();

        return $this->documentCount() >= $this->minDocuments
            && $this->spamDocuments > 0
            && $this->hamDocuments > 0;
    }

    /**
     * Best-effort label: true = spam. Untrained models always answer false.
     */
    public function classify(string $text): bool
    {
        return $this->isTrained() && $this->score($text) >= $this->threshold;
    }

    public function documentCount(): int
    {
        $this->ensureLoaded();

        return $this->spamDocuments + $this->hamDocuments;
    }

    public function tokenCount(): int
    {
        $this->ensureLoaded();

        return array_sum($this->spamTokens) + array_sum($this->hamTokens);
    }

    public function vocabularySize(): int
    {
        $this->ensureLoaded();

        return $this->model()->vocabularySize();
    }

    /**
     * Snapshot of the current model (what would be persisted).
     */
    public function model(): Model
    {
        $this->ensureLoaded();

        return new Model(
            $this->spamTokens,
            $this->hamTokens,
            $this->spamDocuments,
            $this->hamDocuments,
        );
    }

    /**
     * @return array{
     *     spam_documents: int,
     *     ham_documents: int,
     *     documents: int,
     *     tokens: int,
     *     vocabulary: int,
     *     trained: bool
     * }
     */
    public function stats(): array
    {
        $this->ensureLoaded();

        return [
            'spam_documents' => $this->spamDocuments,
            'ham_documents' => $this->hamDocuments,
            'documents' => $this->documentCount(),
            'tokens' => $this->tokenCount(),
            'vocabulary' => $this->vocabularySize(),
            'trained' => $this->isTrained(),
        ];
    }

    /**
     * Persist the current model.
     */
    public function persist(): void
    {
        $this->ensureLoaded();
        $this->storage->save($this->model());
    }

    /**
     * Alias of `persist()`; the Lead's pipeline may call either name.
     */
    public function save(): void
    {
        $this->persist();
    }

    /**
     * Load the persisted model (replacing in-memory state).
     *
     * A failing storage adapter is fail-open: the classifier simply starts
     * untrained instead of breaking the submission pipeline.
     */
    public function load(): void
    {
        try {
            $model = $this->storage->load();
        } catch (Throwable) {
            $model = null;
        }

        $this->apply($model ?? Model::empty());
        $this->loaded = true;
    }

    /**
     * Forget everything: in-memory state and the persisted model.
     */
    public function reset(): void
    {
        $this->apply(Model::empty());
        $this->loaded = true;
        $this->storage->delete();
    }

    private function ensureLoaded(): void
    {
        if (!$this->loaded) {
            $this->load();
        }
    }

    private function apply(Model $model): void
    {
        $this->spamTokens = $model->spamTokens;
        $this->hamTokens = $model->hamTokens;
        $this->spamDocuments = $model->spamDocuments;
        $this->hamDocuments = $model->hamDocuments;
    }
}
