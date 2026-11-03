<?php

declare(strict_types=1);

namespace FormSpamChecker\Exception;

/**
 * Thrown when the configuration is missing a required value or is malformed.
 */
class InvalidConfigException extends \InvalidArgumentException
{
}
