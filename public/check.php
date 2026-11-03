<?php

declare(strict_types=1);

/**
 * HTTP entry point for the spam checker bridge.
 *
 * The application it protects must stay in its own process: this endpoint is a
 * stateless service that answers "clean / suspicious / spam" for one payload.
 * It is safe to expose on an internal interface or to call from Node, Go or
 * Python over localhost.
 */

require dirname(__DIR__) . '/autoload.php';

FormSpamChecker\Http\CheckEndpoint::fromEnvironment()->handle();
