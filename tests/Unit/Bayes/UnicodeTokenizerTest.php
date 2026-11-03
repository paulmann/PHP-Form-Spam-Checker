<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Bayes;

use FormSpamChecker\Bayes\UnicodeTokenizer;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class UnicodeTokenizerTest extends TestCase
{
    public function testLowercasesAndSplitsOnPunctuation(): void
    {
        $tokens = (new UnicodeTokenizer())->tokenize('Hello, WORLD!');

        self::assertSame(['hello' => 1, 'hello world' => 1, 'world' => 1], $tokens);
    }

    public function testSplitsOnMixedSeparatorsAndKeepsDigits(): void
    {
        $tokens = (new UnicodeTokenizer())->tokenize('price:100$ now!');

        self::assertArrayHasKey('price', $tokens);
        self::assertArrayHasKey(100, $tokens);
        self::assertArrayHasKey('now', $tokens);
        self::assertArrayHasKey('price 100', $tokens);
    }

    public function testDropsShortTokens(): void
    {
        $tokens = (new UnicodeTokenizer())->tokenize('I am a big cat');

        self::assertArrayNotHasKey('i', $tokens);
        self::assertArrayNotHasKey('a', $tokens);
        self::assertArrayHasKey('am', $tokens);
        self::assertArrayHasKey('big', $tokens);
        self::assertArrayHasKey('cat', $tokens);
        self::assertArrayHasKey('big cat', $tokens);
    }

    public function testKeepsUnicodeLetters(): void
    {
        $tokens = (new UnicodeTokenizer())->tokenize('Казино 2025 год');

        self::assertArrayHasKey('казино', $tokens);
        self::assertArrayHasKey('2025', $tokens);
        self::assertArrayHasKey('год', $tokens);
        self::assertArrayHasKey('казино 2025', $tokens);
    }

    public function testEmptyInputProducesEmptyBag(): void
    {
        $tokenizer = new UnicodeTokenizer();

        self::assertSame([], $tokenizer->tokenize(''));
        self::assertSame([], $tokenizer->tokenize('   '));
        self::assertSame([], $tokenizer->tokenize('!!! ??? ...'));
    }

    public function testBigramsCanBeDisabled(): void
    {
        $tokens = (new UnicodeTokenizer(bigrams: false))->tokenize('hello world');

        self::assertSame(['hello' => 1, 'world' => 1], $tokens);
    }

    public function testCapsWordsPerDocument(): void
    {
        $tokens = (new UnicodeTokenizer(maxWordsPerDocument: 3))->tokenize('one two three four five');

        self::assertArrayHasKey('one', $tokens);
        self::assertArrayHasKey('two', $tokens);
        self::assertArrayHasKey('three', $tokens);
        self::assertArrayNotHasKey('four', $tokens);
        self::assertArrayNotHasKey('three four', $tokens);
    }

    public function testCapsRepeatedTokenCount(): void
    {
        $tokens = (new UnicodeTokenizer(maxCountPerToken: 2))->tokenize('spam spam spam spam');

        self::assertSame(2, $tokens['spam']);
        self::assertSame(2, $tokens['spam spam']);
    }

    public function testMinLengthOption(): void
    {
        $tokens = (new UnicodeTokenizer(minLength: 3))->tokenize('am big cat');

        self::assertArrayNotHasKey('am', $tokens);
        self::assertArrayHasKey('big', $tokens);
        self::assertArrayHasKey('cat', $tokens);
    }

    public function testTruncatesOverlongText(): void
    {
        $tokens = (new UnicodeTokenizer(maxTextLength: 5))->tokenize('abcdef ghijkl');

        self::assertSame(['abcde' => 1], $tokens);
    }

    public function testDeterministicForSameInput(): void
    {
        $tokenizer = new UnicodeTokenizer();

        self::assertSame(
            $tokenizer->tokenize('Buy now, buy Viagra NOW!'),
            $tokenizer->tokenize('Buy now, buy Viagra NOW!'),
        );
    }

    public function testInvalidUtf8IsIgnored(): void
    {
        self::assertSame([], (new UnicodeTokenizer())->tokenize("\xFF\xFE\x00"));
    }

    public function testRejectsInvalidConfiguration(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new UnicodeTokenizer(minLength: 0);
    }

    public function testRejectsInvalidDocumentCap(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new UnicodeTokenizer(maxWordsPerDocument: 0);
    }

    public function testRejectsInvalidCountCap(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new UnicodeTokenizer(maxCountPerToken: 0);
    }

    public function testRejectsInvalidTextCap(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new UnicodeTokenizer(maxTextLength: 0);
    }
}
