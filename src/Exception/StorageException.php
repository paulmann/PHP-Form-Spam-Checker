<?php

declare(strict_types=1);

namespace FormSpamChecker\Exception;

use RuntimeException;

/**
 * Thrown when the counter storage cannot be read or written.
 */
class StorageException extends RuntimeException {}
