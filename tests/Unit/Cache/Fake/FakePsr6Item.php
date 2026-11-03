<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Cache\Fake;

use DateInterval;
use DateTimeInterface;
use Psr\Cache\CacheItemInterface;
use RuntimeException;

/**
 * PSR-6 item that records the expiration call made by the adapter.
 */
final class FakePsr6Item implements CacheItemInterface
{
    public null|int|DateInterval $lastExpiresAfter = null;

    public bool $expiresAfterCalled = false;

    public ?DateTimeInterface $lastExpiresAt = null;

    private mixed $value = null;

    private bool $hit = false;

    public function __construct(private readonly string $key) {}

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        if (!$this->hit) {
            throw new RuntimeException('Cache miss for key ' . $this->key);
        }

        return $this->value;
    }

    public function isHit(): bool
    {
        return $this->hit;
    }

    public function set(mixed $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function expiresAt(?DateTimeInterface $expiration): static
    {
        $this->lastExpiresAt = $expiration;

        return $this;
    }

    public function expiresAfter(int|DateInterval|null $time): static
    {
        $this->expiresAfterCalled = true;
        $this->lastExpiresAfter = $time;

        return $this;
    }

    public function markHit(bool $hit = true): void
    {
        $this->hit = $hit;
    }
}
