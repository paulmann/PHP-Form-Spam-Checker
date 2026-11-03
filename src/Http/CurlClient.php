<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

/**
 * cURL-based HTTP client, the default transport.
 *
 * Only what the checker needs: no redirects, TLS verification on, hard
 * timeouts, response headers captured for rate-limit introspection.
 */
final readonly class CurlClient implements HttpClientInterface
{
    public function __construct() {}

    public function send(HttpRequest $request): HttpResponse
    {
        if (!\function_exists('curl_init')) {
            throw new HttpClientException('cURL extension is not available.');
        }

        $handle = curl_init();
        if ($handle === false) {
            throw new HttpClientException('curl_init() failed.');
        }

        $responseHeaders = [];
        $headerLines = [];
        foreach ($request->headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $timeoutMs = max(1, (int) ($request->timeout * 1000));

        $url = $request->url;
        if ($url === '') {
            throw new HttpClientException('HTTP request URL must not be empty.');
        }

        $method = $request->method === '' ? 'GET' : $request->method;

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (\count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }

                return \strlen($line);
            },
        ]);

        if ($request->body !== '') {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $request->body);
        }

        $body = curl_exec($handle);
        $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);

        if ($body === false) {
            throw new HttpClientException('HTTP request failed: ' . ($error !== '' ? $error : 'unknown error'));
        }

        return new HttpResponse($status, $responseHeaders, (string) $body);
    }
}
