<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\TimeTrapCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use FormSpamChecker\Token\FormToken;
use PHPUnit\Framework\TestCase;

final class TimeTrapCheckTest extends TestCase
{
    use BuildsSubmissions;

    private const string SECRET = '0123456789abcdef-secret';

    private function config(array $overrides = []): Config
    {
        return new Config([
            'time_trap' => [
                'enabled' => true,
                'secret' => self::SECRET,
                'min_seconds' => 2,
                'max_seconds' => 3600,
                'require_token' => true,
                ...$overrides,
            ],
        ]);
    }

    private function token(int $issuedAt, string $formId = 'contact'): string
    {
        return (new FormToken(self::SECRET))->issue($formId, $issuedAt);
    }

    public function testTokenSubmittedAfterMinimumDelayIsClean(): void
    {
        $now = 1_700_000_000;
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => $this->token($now - 10)], ['now' => $now]),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testTooFastSubmissionIsSpam(): void
    {
        $now = 1_700_000_000;
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => $this->token($now - 1)], ['now' => $now]),
        );

        self::assertSame(Status::Spam, $result->status);
        self::assertStringContainsString('minimum', $result->reason);
    }

    public function testMissingTokenIsSuspiciousWhenRequired(): void
    {
        $result = (new TimeTrapCheck($this->config()))->check($this->submission([]));

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testMissingTokenIsCleanWhenNotRequired(): void
    {
        $result = (new TimeTrapCheck($this->config(['require_token' => false])))
            ->check($this->submission([]));

        self::assertTrue($result->status->isClean());
    }

    public function testForgedTokenIsSpam(): void
    {
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => 'forged.token']),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testTokenFromAnotherFormIsSpam(): void
    {
        $now = 1_700_000_000;
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => $this->token($now - 10, 'register')], ['now' => $now]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testFutureTokenIsSpam(): void
    {
        $now = 1_700_000_000;
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => $this->token($now + 60)], ['now' => $now]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testExpiredTokenIsSuspicious(): void
    {
        $now = 1_700_000_000;
        $result = (new TimeTrapCheck($this->config()))->check(
            $this->submission(['_fs_ts' => $this->token($now - 7200)], ['now' => $now]),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('old', $result->reason);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = $this->config(['enabled' => false]);
        $result = (new TimeTrapCheck($config))->check($this->submission(['_fs_ts' => 'garbage']));

        self::assertTrue($result->status->isClean());
    }

    public function testMisconfiguredSecretFailsOpen(): void
    {
        $config = $this->config(['secret' => 'short']);
        $result = (new TimeTrapCheck($config))->check($this->submission(['_fs_ts' => 'garbage']));

        self::assertTrue($result->status->isClean());
        self::assertStringContainsString('misconfigured', $result->reason);
    }
}
