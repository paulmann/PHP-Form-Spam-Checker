<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Bayes;

use FormSpamChecker\Bayes\CacheModelStorage;
use FormSpamChecker\Bayes\Classifier;
use FormSpamChecker\Bayes\Model;
use FormSpamChecker\Bayes\UnicodeTokenizer;
use FormSpamChecker\Cache\ArrayCache;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ClassifierTest extends TestCase
{
    private const SPAM_TEXT = 'viagra casino bonus free money';
    private const HAM_TEXT = 'hello friend meeting tomorrow';

    public function testUntrainedModelAbstains(): void
    {
        $classifier = $this->make();

        self::assertFalse($classifier->isTrained());
        self::assertSame(0.5, $classifier->score('any text at all'));
        self::assertSame(0, $classifier->documentCount());
        self::assertSame(0, $classifier->tokenCount());
        self::assertSame(0, $classifier->vocabularySize());
        self::assertSame(0.5, $classifier->score(''));
    }

    public function testTrainingSeparatesClasses(): void
    {
        $classifier = $this->trained();

        self::assertTrue($classifier->isTrained());
        self::assertGreaterThan(0.5, $classifier->score(self::SPAM_TEXT));
        self::assertLessThan(0.5, $classifier->score(self::HAM_TEXT));
    }

    public function testIdenticalCorpusIsSymmetric(): void
    {
        $classifier = $this->make();

        $classifier->train('apple banana cherry', true);
        $classifier->train('apple banana cherry', false);

        self::assertSame(0.5, $classifier->score('apple banana cherry'));
    }

    public function testPriorsFollowDocumentCounts(): void
    {
        $classifier = $this->make();

        $classifier->train('apple banana', true);

        for ($index = 0; $index < 5; $index++) {
            $classifier->train('apple banana', false);
        }

        // Identical token distribution on both sides: only the priors decide,
        // and they are (1 + 1) / (1 + 5 + 2) = 0.25 for spam.
        self::assertEqualsWithDelta(0.25, $classifier->score('apple banana'), 1e-9);
    }

    public function testMinDocumentsGate(): void
    {
        $classifier = $this->make(minDocuments: 3);

        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train(self::HAM_TEXT, false);

        self::assertFalse($classifier->isTrained());
        self::assertSame(0.5, $classifier->score(self::SPAM_TEXT));

        $classifier->train('casino poker bonus', true);

        self::assertTrue($classifier->isTrained());
        self::assertGreaterThan(0.5, $classifier->score(self::SPAM_TEXT));
    }

    public function testUntrainRestoresState(): void
    {
        $classifier = $this->make();

        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train(self::HAM_TEXT, false);

        $classifier->untrain(self::SPAM_TEXT, true);

        self::assertSame(0, $classifier->stats()['spam_documents']);
        self::assertFalse($classifier->isTrained());
        self::assertSame(0.5, $classifier->score(self::SPAM_TEXT));
    }

    public function testUntrainRemovesZeroCounts(): void
    {
        $classifier = $this->make(minDocuments: 1);

        $classifier->train('alpha beta', true);
        $classifier->untrain('alpha beta', true);

        self::assertSame(0, $classifier->tokenCount());
        self::assertSame(0, $classifier->vocabularySize());
        self::assertSame(0, $classifier->documentCount());
    }

    public function testEmptyDocumentsAreIgnored(): void
    {
        $classifier = $this->make(minDocuments: 1);

        $classifier->train('', true);
        $classifier->train('   ', true);
        $classifier->train('!!! ???', true);

        self::assertSame(0, $classifier->documentCount());
        self::assertFalse($classifier->isTrained());
    }

    public function testTokenAndVocabularyCounts(): void
    {
        $classifier = $this->make();

        $classifier->train('buy viagra now', true);
        $classifier->train('hello friend', false);

        // spam: buy, viagra, now + 2 bigrams = 5 tokens; ham: 3 tokens.
        self::assertSame(8, $classifier->tokenCount());
        self::assertSame(8, $classifier->vocabularySize());
        self::assertSame(2, $classifier->documentCount());
    }

    public function testPersistenceRoundTripWithLazyLoad(): void
    {
        $cache = new ArrayCache(1000);
        $storage = new CacheModelStorage($cache);

        $first = new Classifier($storage, 2);
        $first->train(self::SPAM_TEXT, true);
        $first->train('casino poker viagra', true);
        $first->train(self::HAM_TEXT, false);
        $first->train('hello friend dinner tonight', false);
        $first->persist();

        $second = new Classifier($storage, 2);

        self::assertTrue($second->isTrained());
        self::assertSame($first->documentCount(), $second->documentCount());
        self::assertSame($first->tokenCount(), $second->tokenCount());
        self::assertSame($first->score(self::SPAM_TEXT), $second->score(self::SPAM_TEXT));
    }

    public function testExplicitLoadReplacesState(): void
    {
        $cache = new ArrayCache(1000);
        $storage = new CacheModelStorage($cache);
        $storage->save(new Model(['viagra' => 3], ['hello' => 3], 2, 2));

        $classifier = new Classifier($storage, 1);
        $classifier->load();

        self::assertSame(4, $classifier->documentCount());
        self::assertSame(6, $classifier->tokenCount());
        self::assertTrue($classifier->isTrained());
    }

    public function testResetClearsStateAndStorage(): void
    {
        $cache = new ArrayCache(1000);
        $storage = new CacheModelStorage($cache);
        $classifier = new Classifier($storage, 1);
        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train(self::HAM_TEXT, false);
        $classifier->persist();

        $classifier->reset();

        self::assertSame(0, $classifier->documentCount());
        self::assertFalse($classifier->isTrained());
        self::assertNull($storage->load());
    }

    public function testTrainFromStringAndList(): void
    {
        $classifier = $this->make(minDocuments: 4);

        self::assertSame(3, $classifier->trainFromList(['aaa bbb', 'ccc ddd', 'eee fff'], true));
        self::assertSame(0, $classifier->trainFromList([''], true));
        $classifier->trainFromString('hello friend', false);

        self::assertSame(4, $classifier->documentCount());
        self::assertTrue($classifier->isTrained());
    }

    public function testProbabilityIsClamped(): void
    {
        $classifier = $this->make();

        for ($index = 0; $index < 5; $index++) {
            $classifier->train('viagra viagra viagra', true);
        }
        $classifier->train('hello friend meeting', false);
        $classifier->train('hello friend dinner', false);

        $spamProbability = $classifier->score('viagra viagra viagra viagra viagra');
        $hamProbability = $classifier->score('hello friend meeting dinner');

        self::assertGreaterThanOrEqual(0.5, $spamProbability);
        self::assertLessThanOrEqual(0.99, $spamProbability);
        self::assertLessThanOrEqual(0.5, $hamProbability);
        self::assertGreaterThanOrEqual(0.01, $hamProbability);
    }

    public function testClassifyUsesThreshold(): void
    {
        $classifier = $this->make(threshold: 0.5);

        self::assertFalse($classifier->classify(self::SPAM_TEXT), 'untrained models never classify as spam');

        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train(self::HAM_TEXT, false);

        self::assertTrue($classifier->classify(self::SPAM_TEXT));
        self::assertFalse($classifier->classify(self::HAM_TEXT));
    }

    public function testAccessors(): void
    {
        $classifier = $this->make(minDocuments: 3, threshold: 0.5);

        self::assertSame(3, $classifier->minDocuments());
        self::assertSame(0.5, $classifier->threshold());
        self::assertInstanceOf(UnicodeTokenizer::class, $classifier->tokenizer());
        self::assertInstanceOf(CacheModelStorage::class, $classifier->storage());
    }

    public function testModelSnapshot(): void
    {
        $classifier = $this->make();
        $classifier->train(self::SPAM_TEXT, true);

        $model = $classifier->model();

        self::assertSame(1, $model->documents());
        self::assertSame($classifier->tokenCount(), $model->tokenTotal());
        self::assertSame($classifier->vocabularySize(), $model->vocabularySize());
    }

    public function testStatsShape(): void
    {
        $classifier = $this->trained();
        $stats = $classifier->stats();

        self::assertSame(2, $stats['spam_documents']);
        self::assertSame(2, $stats['ham_documents']);
        self::assertSame(4, $stats['documents']);
        self::assertTrue($stats['trained']);
        self::assertGreaterThan(0, $stats['tokens']);
        self::assertGreaterThan(0, $stats['vocabulary']);
    }

    public function testFailingStorageFailsOpen(): void
    {
        $storage = new class implements \FormSpamChecker\Bayes\ModelStorageInterface {
            public function load(): ?Model
            {
                throw new RuntimeException('storage is down');
            }

            public function save(Model $model): void
            {
                throw new RuntimeException('storage is down');
            }

            public function delete(): void {}
        };

        $classifier = new Classifier($storage, 1);

        self::assertFalse($classifier->isTrained());
        self::assertSame(0.5, $classifier->score('any text'));
    }

    public function testRejectsNegativeMinDocuments(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->make(minDocuments: -1);
    }

    public function testRejectsThresholdAboveOne(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->make(threshold: 1.5);
    }

    public function testRejectsNegativeThreshold(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->make(threshold: -0.1);
    }

    private function make(int $minDocuments = 2, float $threshold = 0.92): Classifier
    {
        return new Classifier(new CacheModelStorage(new ArrayCache(1000)), $minDocuments, $threshold);
    }

    private function trained(): Classifier
    {
        $classifier = $this->make();

        $classifier->train(self::SPAM_TEXT, true);
        $classifier->train('casino poker viagra', true);
        $classifier->train(self::HAM_TEXT, false);
        $classifier->train('hello friend dinner tonight', false);

        return $classifier;
    }
}
