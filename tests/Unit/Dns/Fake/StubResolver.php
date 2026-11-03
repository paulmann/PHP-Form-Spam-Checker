<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Dns\Fake;

use FormSpamChecker\Dns\ResolverInterface;

/**
 * In-memory resolver: tests declare the zone contents and assert on the queries
 * the code under test actually performed.
 */
final class StubResolver implements ResolverInterface
{
    /**
     * @var array<string, list<string>>
     */
    public array $txtRecords = [];

    /**
     * @var array<string, list<string>>
     */
    public array $aRecords = [];

    /**
     * @var array<string, list<string>>
     */
    public array $mxRecords = [];

    /**
     * @var list<string>
     */
    public array $queries = [];

    /**
     * @return list<string>
     */
    public function txt(string $name): array
    {
        $key = strtolower(rtrim($name, '.'));
        $this->queries[] = 'txt:' . $key;

        return $this->txtRecords[$key] ?? [];
    }

    /**
     * @return list<string>
     */
    public function a(string $name): array
    {
        $key = strtolower(rtrim($name, '.'));
        $this->queries[] = 'a:' . $key;

        return $this->aRecords[$key] ?? [];
    }

    /**
     * @return list<string>
     */
    public function mx(string $name): array
    {
        $key = strtolower(rtrim($name, '.'));
        $this->queries[] = 'mx:' . $key;

        return $this->mxRecords[$key] ?? [];
    }
}
