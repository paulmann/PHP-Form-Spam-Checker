<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

use RuntimeException;

/**
 * Transport-level failure: DNS error, connect timeout, TLS failure.
 *
 * Checks catch this and fail open; the message never contains the API key.
 */
class HttpClientException extends RuntimeException {}
