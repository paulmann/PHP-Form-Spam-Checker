<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Bayes;

use FormSpamChecker\Bayes\Model;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ModelTest extends TestCase
{
    public function testEmptyModel(): void
    {
        $model = Model::empty();

        self::assertTrue($model->isEmpty());
        self::assertSame(0, $model->documents());
        self::assertSame(0, $model->tokenTotal());
        self::assertSame(0, $model->vocabularySize());
        self::assertSame(Model::VERSION, $model->version);
    }

    public function testCountsAndVocabularyUnion(): void
    {
        $model = new Model(['a' => 2], ['a' => 1, 'b' => 3], 1, 2);

        self::assertFalse($model->isEmpty());
        self::assertSame(3, $model->documents());
        self::assertSame(6, $model->tokenTotal());
        self::assertSame(2, $model->vocabularySize());
    }

    public function testToArrayIsSortedAndVersioned(): void
    {
        $model = new Model(['b' => 2, 'a' => 1], ['c' => 3], 1, 2);
        $array = $model->toArray();

        self::assertSame(['a', 'b'], array_keys($array['spam_tokens']));
        self::assertSame(Model::VERSION, $array['version']);
        self::assertSame(1, $array['spam_documents']);
        self::assertSame(2, $array['ham_documents']);
    }

    public function testRoundTrip(): void
    {
        $model = new Model(['viagra' => 2, 'казино' => 1], ['hello' => 4], 3, 5);
        $restored = Model::fromArray($model->toArray());

        self::assertInstanceOf(Model::class, $restored);
        self::assertSame($model->toArray(), $restored->toArray());
    }

    public function testRejectsFutureVersion(): void
    {
        self::assertNull(Model::fromArray(['version' => 99, 'spam_tokens' => []]));
    }

    public function testRejectsInvalidTokenValues(): void
    {
        self::assertNull(Model::fromArray(['spam_tokens' => ['a' => 0]]));
        self::assertNull(Model::fromArray(['spam_tokens' => ['a' => 'x']]));
        self::assertNull(Model::fromArray(['spam_tokens' => ['a' => ['nested']]]));
        self::assertNull(Model::fromArray(['ham_tokens' => 'not-an-array']));
    }

    public function testRejectsNegativeDocumentCounts(): void
    {
        self::assertNull(Model::fromArray(['spam_documents' => -1]));
    }

    public function testAcceptsNumericStringTokenKeysAfterJsonDecode(): void
    {
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode('{"spam_tokens":{"2025":3}}', true, 8, JSON_THROW_ON_ERROR);

        $model = Model::fromArray($decoded);

        self::assertInstanceOf(Model::class, $model);
        self::assertArrayHasKey(2025, $model->spamTokens);
        self::assertSame(3, $model->spamTokens[2025]);
    }

    public function testConstructorRejectsNegativeDocuments(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Model(spamDocuments: -1);
    }
}
