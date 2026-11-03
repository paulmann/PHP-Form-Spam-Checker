<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\EmailCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class EmailCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testValidEmailIsClean(): void
    {
        $result = (new EmailCheck(new Config()))->check(
            $this->submission(['email' => 'ivan.petrov@example.ru']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testEmptyFieldsAreClean(): void
    {
        $result = (new EmailCheck(new Config()))->check($this->submission([]));

        self::assertTrue($result->status->isClean());
    }

    public function testInvalidEmailIsSuspicious(): void
    {
        $result = (new EmailCheck(new Config()))->check(
            $this->submission(['email' => 'not-an-email']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('invalid', $result->reason);
    }

    public function testDisposableEmailIsSuspicious(): void
    {
        $result = (new EmailCheck(new Config()))->check(
            $this->submission(['email' => 'spam@mailinator.com']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('disposable', $result->reason);
    }

    public function testSubdomainOfDisposableDomainIsDetected(): void
    {
        $result = (new EmailCheck(new Config()))->check(
            $this->submission(['email' => 'spam@inbox.mailinator.com']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testSecondaryFieldIsAlsoChecked(): void
    {
        $result = (new EmailCheck(new Config()))->check(
            $this->submission(['email' => 'ok@example.ru', 'personalEmail' => 'x@yopmail.com']),
        );

        self::assertSame(Status::Suspicious, $result->status);
        self::assertStringContainsString('personalEmail', $result->reason);
    }

    public function testCustomDisposableDomain(): void
    {
        $config = new Config(['email' => ['disposable_domains' => ['throwaway.example']]]);
        $result = (new EmailCheck($config))->check(
            $this->submission(['email' => 'x@throwaway.example']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['email' => ['enabled' => false]]);
        $result = (new EmailCheck($config))->check(
            $this->submission(['email' => 'not-an-email']),
        );

        self::assertTrue($result->status->isClean());
    }
}
