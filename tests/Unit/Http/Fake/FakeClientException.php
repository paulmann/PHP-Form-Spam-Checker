<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Http\Fake;

use RuntimeException;

/**
 * PSR-18 client exception for the adapter's failure path.
 */
final class FakeClientException extends RuntimeException implements \Psr\Http\Client\ClientExceptionInterface {}
