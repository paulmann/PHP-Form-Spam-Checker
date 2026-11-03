<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Status;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class DataTest extends TestCase
{
    public function testRequestDataFieldAccessAndNormalisation(): void
    {
        $request = new RequestData([
            'name' => '  Иван  ',
            'count' => 42,
            'flag' => true,
            'nested' => ['a' => 'b'],
            'empty' => '   ',
        ]);

        self::assertTrue($request->hasField('name'));
        self::assertFalse($request->hasField('missing'));
        self::assertSame('Иван', $request->field('name'));
        self::assertSame('42', $request->field('count'));
        self::assertSame('1', $request->field('flag'));
        self::assertSame('', $request->field('nested'));
        self::assertSame('', $request->field('missing'));
        self::assertSame('', $request->field('empty'));
    }

    public function testRequestDataContentTextFirstAndSample(): void
    {
        $request = new RequestData([
            'name' => 'Иван',
            'message' => "Первая строка\nВторая",
            'website' => 'spam',
            'empty' => '',
        ]);

        self::assertSame(['name' => 'Иван', 'message' => "Первая строка\nВторая"], $request->content(['website']));
        self::assertStringContainsString('Иван', $request->text(['website']));
        self::assertSame('Иван', $request->first(['missing', 'name']));
        self::assertSame('', $request->first(['missing']));
        self::assertArrayNotHasKey('website', $request->content(['website']));
        self::assertSame('Иван', $request->sample([], 10)['name']);
        self::assertStringNotContainsString("\n", $request->sample([], 20)['message']);
    }

    public function testRequestDataHeadersAreCaseInsensitive(): void
    {
        $request = new RequestData(headers: ['user-agent' => 'UA/1.0', 'referer' => 'https://ref']);

        self::assertSame('UA/1.0', $request->header('User-Agent'));
        self::assertSame('UA/1.0', $request->userAgent());
        self::assertSame('https://ref', $request->referer());
        self::assertSame('', $request->header('x-missing'));
    }

    public function testRequestDataWithMethodsReturnNewInstances(): void
    {
        $request = new RequestData(['a' => '1'], formId: 'contact');
        $withFields = $request->withFields(['b' => '2']);
        $withForm = $request->withFormId('register');

        self::assertSame(['a' => '1'], $request->fields);
        self::assertSame(['b' => '2'], $withFields->fields);
        self::assertSame('register', $withForm->formId);
        self::assertSame('contact', $request->formId);
    }

    public function testRequestDataFromGlobals(): void
    {
        $previous = $_SERVER;
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.7',
            'HTTP_USER_AGENT' => 'UA/2.0',
            'HTTP_REFERER' => 'https://example.ru/contacts/',
            'REQUEST_METHOD' => 'post',
            'REQUEST_URI' => '/api/lead',
            'QUERY_STRING' => 'a=1&b=2',
        ];

        try {
            $request = RequestData::fromGlobals($_SERVER, ['name' => 'Иван'], 'lead');
        } finally {
            $_SERVER = $previous;
        }

        self::assertSame('203.0.113.7', $request->ip);
        self::assertSame('POST', $request->method);
        self::assertSame('/api/lead', $request->uri);
        self::assertSame(['a' => '1', 'b' => '2'], $request->query);
        self::assertSame('UA/2.0', $request->header('user-agent'));
        self::assertSame('Иван', $request->field('name'));
        self::assertSame('lead', $request->formId);
    }

    public function testCheckOutcomeFactoriesAndFlags(): void
    {
        self::assertFalse(CheckOutcome::ham('x')->isFlagged());
        self::assertSame(CheckStatus::HAM, CheckOutcome::ham('x')->status);
        self::assertTrue(CheckOutcome::suspicious('x', 20, 'reason')->isFlagged());
        self::assertSame(0, CheckOutcome::suspicious('x', 20, 'reason')->status->value === 'ham' ? 0 : 1);
        self::assertTrue(CheckOutcome::spam('x', 'hard')->isFlagged());
        self::assertSame(CheckStatus::SPAM, CheckOutcome::spam('x', 'hard')->status);
        self::assertFalse(CheckOutcome::uncertain('x', 'n/a')->isFlagged());
        self::assertFalse(CheckOutcome::error('x', 'boom')->isFlagged());
        self::assertStringContainsString('fail open', CheckOutcome::error('x', 'boom')->reason);
    }

    public function testCheckOutcomeRejectsInvalidScores(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CheckOutcome('x', CheckStatus::HAM, 101);
    }

    public function testCheckOutcomeToArray(): void
    {
        $outcome = CheckOutcome::spam('xss', 'script', ['match' => '<script>']);
        $array = $outcome->toArray();

        self::assertSame('xss', $array['check']);
        self::assertSame('spam', $array['status']);
        self::assertSame(100, $array['score']);
        self::assertSame('script', $array['reason']);
        self::assertSame(['match' => '<script>'], $array['evidence']);
    }

    public function testVerdictAggregationThresholds(): void
    {
        $config = new Config(['thresholds' => ['suspicious' => 30, 'spam' => 60]]);

        self::assertTrue(Verdict::fromOutcomes([CheckOutcome::ham('a')], $config, false, 0)->isClean());
        self::assertTrue(Verdict::fromOutcomes([CheckOutcome::suspicious('a', 35, 's')], $config, false, 35)->isSuspicious());
        self::assertTrue(Verdict::fromOutcomes([CheckOutcome::suspicious('a', 40, 's'), CheckOutcome::suspicious('b', 25, 's')], $config, false, 65)->isSpam());
        self::assertSame(100, Verdict::fromOutcomes([CheckOutcome::suspicious('a', 90, 's'), CheckOutcome::suspicious('b', 90, 's')], $config, false, 180)->score);
    }

    public function testVerdictHardSpamWins(): void
    {
        $verdict = Verdict::fromOutcomes([CheckOutcome::spam('a', 'hard')], new Config(), true, 1);

        self::assertSame(Status::Spam, $verdict->status);
        self::assertSame(['a: hard'], $verdict->reasons());
        self::assertCount(1, $verdict->flagged());
        self::assertSame('spam', $verdict->toArray()['status']);
    }

    public function testVerdictFromArrayRoundTrip(): void
    {
        $original = Verdict::fromOutcomes([CheckOutcome::spam('honeypot', 'filled', ['x' => 1])], new Config(), true, 100);
        $restored = Verdict::fromArray($original->toArray());

        self::assertSame($original->status, $restored->status);
        self::assertSame($original->score, $restored->score);
        self::assertSame($original->reasons(), $restored->reasons());
        self::assertSame(CheckStatus::SPAM, $restored->outcomes[0]->status);
    }

    public function testVerdictRejectsInvalidScore(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Verdict(Status::Clean, 101);
    }

    public function testConfigV2Defaults(): void
    {
        $config = new Config();

        self::assertTrue($config->bool('pipeline.stop_on_spam'));
        self::assertFalse($config->bool('abuseipdb.enabled'));
        self::assertSame(90, $config->int('abuseipdb.threshold'));
        self::assertSame(['zen.spamhaus.org', 'bl.spamcop.net'], $config->array('dnsbl.zones'));
        self::assertSame(0.92, $config->float('bayes.threshold'));
        self::assertSame('monitor', $config->string('waf.mode'));
        self::assertFalse($config->bool('waf.enabled'));
        self::assertTrue($config->bool('behavioral.honeypot.dynamic'));
    }

    public function testConfigCacheAndBayesPaths(): void
    {
        $config = new Config(['storage' => ['path' => '/tmp/pfsc']]);

        self::assertSame($config->storagePath() . DIRECTORY_SEPARATOR . 'cache', $config->cachePath());
        self::assertSame($config->storagePath() . DIRECTORY_SEPARATOR . 'bayes', $config->bayesStoragePath());

        $custom = new Config(['cache' => ['path' => '/tmp/c'], 'bayes' => ['storage_path' => '/tmp/b']]);
        self::assertSame('/tmp/c', $custom->cachePath());
        self::assertSame('/tmp/b', $custom->bayesStoragePath());
    }
}
