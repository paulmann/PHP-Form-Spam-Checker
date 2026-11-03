<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Checks;

use FormSpamChecker\Checks\SqlInjectionCheck;
use FormSpamChecker\Config;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\BuildsSubmissions;
use PHPUnit\Framework\TestCase;

final class SqlInjectionCheckTest extends TestCase
{
    use BuildsSubmissions;

    public function testNormalTextIsClean(): void
    {
        $result = (new SqlInjectionCheck(new Config()))->check(
            $this->submission(['message' => 'Прибор BCT-48-150, серийный номер 0226016.']),
        );

        self::assertTrue($result->status->isClean());
    }

    public function testUnionSelectIsSpam(): void
    {
        $result = (new SqlInjectionCheck(new Config()))->check(
            $this->submission(['message' => "1 UNION SELECT username FROM users"]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testDropTableIsSpam(): void
    {
        $result = (new SqlInjectionCheck(new Config()))->check(
            $this->submission(['message' => "'; DROP TABLE requests; --"]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testTautologyIsSpam(): void
    {
        $result = (new SqlInjectionCheck(new Config()))->check(
            $this->submission(['message' => "admin' OR 1=1 --"]),
        );

        self::assertSame(Status::Spam, $result->status);
    }

    public function testWeakFragmentIsSuspicious(): void
    {
        $result = (new SqlInjectionCheck(new Config()))->check(
            $this->submission(['message' => 'select the report from the list']),
        );

        self::assertSame(Status::Suspicious, $result->status);
    }

    public function testDisabledCheckIsClean(): void
    {
        $config = new Config(['sql_injection' => ['enabled' => false]]);
        $result = (new SqlInjectionCheck($config))->check(
            $this->submission(['message' => 'UNION SELECT 1']),
        );

        self::assertTrue($result->status->isClean());
    }
}
