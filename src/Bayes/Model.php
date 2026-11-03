<?php

declare(strict_types=1);

namespace FormSpamChecker\Bayes;

use InvalidArgumentException;

/**
 * Immutable Bayesian model: per-class token counts and trained document counts.
 *
 * The model is a plain value object, so it can be JSON-encoded and kept in any
 * `CacheInterface` implementation. Tokens with a zero count are never stored,
 * which keeps the persisted form compact.
 */
final readonly class Model
{
    public const VERSION = 1;

    /**
     * @param array<string, int> $spamTokens token => count in spam documents
     * @param array<string, int> $hamTokens  token => count in ham documents
     */
    public function __construct(
        public array $spamTokens = [],
        public array $hamTokens = [],
        public int $spamDocuments = 0,
        public int $hamDocuments = 0,
        public int $version = self::VERSION,
    ) {
        if ($this->spamDocuments < 0 || $this->hamDocuments < 0) {
            throw new InvalidArgumentException('Document counts must not be negative.');
        }
    }

    public static function empty(): self
    {
        return new self();
    }

    public function isEmpty(): bool
    {
        return $this->spamTokens === []
            && $this->hamTokens === []
            && $this->spamDocuments === 0
            && $this->hamDocuments === 0;
    }

    public function documents(): int
    {
        return $this->spamDocuments + $this->hamDocuments;
    }

    public function tokenTotal(): int
    {
        return array_sum($this->spamTokens) + array_sum($this->hamTokens);
    }

    public function vocabularySize(): int
    {
        $vocabulary = [];
        foreach ($this->spamTokens as $token => $count) {
            $vocabulary[$token] = true;
        }
        foreach ($this->hamTokens as $token => $count) {
            $vocabulary[$token] = true;
        }

        return \count($vocabulary);
    }

    /**
     * @return array{
     *     version: int,
     *     spam_tokens: array<string, int>,
     *     ham_tokens: array<string, int>,
     *     spam_documents: int,
     *     ham_documents: int
     * }
     */
    public function toArray(): array
    {
        $spamTokens = $this->spamTokens;
        $hamTokens = $this->hamTokens;
        ksort($spamTokens);
        ksort($hamTokens);

        return [
            'version' => $this->version,
            'spam_tokens' => $spamTokens,
            'ham_tokens' => $hamTokens,
            'spam_documents' => $this->spamDocuments,
            'ham_documents' => $this->hamDocuments,
        ];
    }

    /**
     * Build a model from decoded JSON, or null when the payload is not a model.
     *
     * Unknown future versions are rejected as well: silently reading a newer
     * format could corrupt training data.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $version = $data['version'] ?? self::VERSION;

        if (!\is_int($version) || $version < 1 || $version > self::VERSION) {
            return null;
        }

        $spamTokens = self::readTokens($data['spam_tokens'] ?? []);
        $hamTokens = self::readTokens($data['ham_tokens'] ?? []);

        if ($spamTokens === null || $hamTokens === null) {
            return null;
        }

        $spamDocuments = $data['spam_documents'] ?? 0;
        $hamDocuments = $data['ham_documents'] ?? 0;

        if (!\is_int($spamDocuments) || !\is_int($hamDocuments) || $spamDocuments < 0 || $hamDocuments < 0) {
            return null;
        }

        return new self($spamTokens, $hamTokens, $spamDocuments, $hamDocuments, $version);
    }

    /**
     * @return array<string, int>|null
     */
    private static function readTokens(mixed $value): ?array
    {
        if (!\is_array($value)) {
            return null;
        }

        $tokens = [];
        foreach ($value as $token => $count) {
            if (!\is_int($count) || $count < 1) {
                return null;
            }

            $tokens[(string) $token] = $count;
        }

        return $tokens;
    }
}
