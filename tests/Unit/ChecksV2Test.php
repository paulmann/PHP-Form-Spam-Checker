<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Check\EmailCheck;
use FormSpamChecker\Check\HoneypotCheck;
use FormSpamChecker\Check\KeywordCheck;
use FormSpamChecker\Check\LanguageCheck;
use FormSpamChecker\Check\LengthCheck;
use FormSpamChecker\Check\LinkCheck;
use FormSpamChecker\Check\RateLimitCheck;
use FormSpamChecker\Check\RepetitionCheck;
use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Check\SqlInjectionCheck;
use FormSpamChecker\Check\TimeTrapCheck;
use FormSpamChecker\Check\UserAgentCheck;
use FormSpamChecker\Check\XssCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use FormSpamChecker\Token\FormToken;
use PHPUnit\Framework\Attributes\DataProvider;

final class ChecksV2Test extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    private function request(array $fields, array $headers = [], ?int $now = null, string $formId = 'contact', string $ip = '203.0.113.10'): RequestData
    {
        $headers['user-agent'] ??= self::UA;

        return new RequestData($fields, $ip, $headers, [], [], 'POST', '/form', '', $now ?? 1_700_000_000, $formId);
    }

    public function testHoneypotFilledIsSpam(): void
    {
        $outcome = (new HoneypotCheck(new Config()))->check($this->request(['website' => 'http://spam']));

        self::assertSame(CheckStatus::SPAM, $outcome->status);
        self::assertSame('honeypot', $outcome->check);
    }

    public function testHoneypotEmptyAndDisabled(): void
    {
        self::assertSame(CheckStatus::HAM, (new HoneypotCheck(new Config()))->check($this->request(['website' => '']))->status);
        self::assertSame(
            CheckStatus::HAM,
            (new HoneypotCheck(new Config(['honeypot' => ['enabled' => false]])))->check($this->request(['website' => 'x']))->status,
        );
    }

    public function testTimeTrapValidTooFastForgedExpiredMissing(): void
    {
        $now = 1_700_000_000;
        $secret = '0123456789abcdef-secret';
        $config = new Config(['time_trap' => ['enabled' => true, 'secret' => $secret, 'min_seconds' => 2, 'max_seconds' => 3600]]);
        $check = new TimeTrapCheck($config);
        $token = (new FormToken($secret))->issue('contact', $now - 10);

        self::assertSame(CheckStatus::HAM, $check->check($this->request(['_fs_ts' => $token], [], $now))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['_fs_ts' => (new FormToken($secret))->issue('contact', $now - 1)], [], $now))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['_fs_ts' => 'forged.token'], [], $now))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['_fs_ts' => (new FormToken($secret))->issue('contact', $now - 7200)], [], $now))->status);
        self::assertSame(
            CheckStatus::HAM,
            (new TimeTrapCheck(new Config(['time_trap' => ['enabled' => false]])))->check($this->request([]))->status,
        );
    }

    #[DataProvider('userAgents')]
    public function testUserAgent(string $ua, CheckStatus $expected): void
    {
        $outcome = (new UserAgentCheck(new Config()))->check($this->request([], ['user-agent' => $ua]));

        self::assertSame($expected, $outcome->status);
    }

    /**
     * @return iterable<string, array{string, CheckStatus}>
     */
    public static function userAgents(): iterable
    {
        yield 'browser' => [self::UA, CheckStatus::HAM];
        yield 'curl' => ['curl/8.5.0', CheckStatus::SPAM];
        yield 'headless' => ['Mozilla/5.0 HeadlessChrome/140.0', CheckStatus::SPAM];
        yield 'scanner' => ['Mozilla/5.0 (compatible; SQLSpider/1.7.0)', CheckStatus::SPAM];
        yield 'empty' => ['', CheckStatus::HAM];
    }

    public function testEmptyUserAgentIsSuspiciousWhenNotAllowed(): void
    {
        $outcome = (new UserAgentCheck(new Config()))->check(new RequestData([]));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertSame(40, $outcome->score);
    }

    public function testRateLimit(): void
    {
        $storage = new MemoryStorage();
        $check = new RateLimitCheck(new Config(['rate_limit' => ['max' => 2]]), $storage);

        self::assertSame(CheckStatus::HAM, $check->check($this->request([]))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request([]))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request([]))->status);
    }

    public function testKeywordScoringAndDisabled(): void
    {
        $check = new KeywordCheck(new Config());
        $outcome = $check->check($this->request(['message' => 'казино, ставки на спорт, биткоин']));

        self::assertSame(CheckStatus::HAM, $outcome->status);
        self::assertGreaterThan(0, $outcome->score);
        self::assertSame(CheckStatus::HAM, (new KeywordCheck(new Config(['keywords' => ['enabled' => false]])))->check($this->request(['message' => 'казино']))->status);
    }

    public function testLinkCheck(): void
    {
        $check = new LinkCheck(new Config(['links' => ['max' => 1]]));

        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'https://example.ru/a']))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'https://a.ru https://b.ru https://c.ru']))->status);
        self::assertGreaterThan(0, $check->check($this->request(['message' => 'https://a.ru https://b.ru https://c.ru']))->score);
    }

    public function testSqlInjectionStrongAndWeak(): void
    {
        $check = new SqlInjectionCheck(new Config());

        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['message' => '1 UNION SELECT password FROM users']))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['message' => "'; DROP TABLE users; --"]))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'select the report from the list']))->status);
    }

    public function testXss(): void
    {
        $check = new XssCheck(new Config());

        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['message' => '<script>alert(1)</script>']))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => '&#60;script&#62;alert(1)&#60;/script&#62;']))->status);
    }

    public function testEmailQuality(): void
    {
        $check = new EmailCheck(new Config());

        self::assertSame(CheckStatus::HAM, $check->check($this->request(['email' => 'ivan@example.ru']))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['email' => 'not-an-email']))->status);
        self::assertGreaterThan(0, $check->check($this->request(['email' => 'x@mailinator.com']))->score);
        self::assertSame(CheckStatus::HAM, (new EmailCheck(new Config(['email' => ['enabled' => false]])))->check($this->request(['email' => 'bad']))->status);
    }

    public function testLengthAndControlCharacters(): void
    {
        $config = new Config(['length' => ['max' => 20, 'hard_max' => 50]]);
        $check = new LengthCheck($config);

        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'ok']))->status);
        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => str_repeat('а', 30)]))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['message' => str_repeat('а', 60)]))->status);
        self::assertSame(CheckStatus::SPAM, $check->check($this->request(['message' => "text\x00null"]))->status);
    }

    public function testRepetition(): void
    {
        $check = new RepetitionCheck(new Config(['repetition' => ['min_run' => 5]]));

        self::assertSame(CheckStatus::HAM, $check->check($this->request(['message' => 'aaaaaaaaaa']))->status);
        self::assertGreaterThan(0, $check->check($this->request(['message' => 'купить купить купить купить']))->score);
        self::assertGreaterThan(0, $check->check($this->request(['message' => 'aaaaaaaaaa']))->score);
    }

    public function testLanguage(): void
    {
        $enabled = new LanguageCheck(new Config(['language' => ['enabled' => true]]));

        self::assertGreaterThan(0, $enabled->check($this->request(['message' => 'Пpивет, нужен отчёт']))->score);
        self::assertSame(0, $enabled->check($this->request(['message' => 'Привет, нужен отчёт']))->score);
        self::assertSame(CheckStatus::HAM, (new LanguageCheck(new Config()))->check($this->request(['message' => 'Пpивет']))->status);
    }

    public function testEveryCheckImplementsContractAndReturnsOutcome(): void
    {
        $checks = [
            new HoneypotCheck(new Config()),
            new TimeTrapCheck(new Config()),
            new UserAgentCheck(new Config()),
            new RateLimitCheck(new Config(), new MemoryStorage()),
            new LengthCheck(new Config()),
            new SqlInjectionCheck(new Config()),
            new XssCheck(new Config()),
            new KeywordCheck(new Config()),
            new LinkCheck(new Config()),
            new EmailCheck(new Config()),
            new RepetitionCheck(new Config()),
            new LanguageCheck(new Config()),
        ];

        foreach ($checks as $check) {
            self::assertInstanceOf(SpamCheckInterface::class, $check);
            self::assertNotSame('', $check->name());
            self::assertInstanceOf(CheckOutcome::class, $check->check($this->request(['message' => 'нормальный текст'])));
        }
    }
}
