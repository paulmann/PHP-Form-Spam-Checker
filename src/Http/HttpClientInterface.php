<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

/**
 * Minimal HTTP transport abstraction (PSR-18 shaped).
 *
 * The library ships a cURL implementation and a PSR-18 adapter; checks depend
 * only on this interface, which makes them testable without network access.
 */
interface HttpClientInterface
{
    public function send(HttpRequest $request): HttpResponse;
}
