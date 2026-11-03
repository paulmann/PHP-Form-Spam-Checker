<?php

declare(strict_types=1);

/**
 * Client example for the HTTP bridge (public/check.php).
 *
 * Useful when the form handler lives in another language: it POSTs the
 * submission as JSON and receives the verdict.
 */

use FormSpamChecker\Config;
use FormSpamChecker\Http\CheckEndpoint;

require dirname(__DIR__) . '/autoload.php';

// Server side, for illustration: the endpoint is usually deployed separately.
$config = Config::fromArray(['endpoint' => ['key' => 'example-shared-key']]);
$endpoint = new CheckEndpoint($config);

$payload = [
    'form' => 'contact',
    'fields' => [
        'name' => 'Иван Петров',
        'email' => 'ivan@example.com',
        'message' => 'Прошу перезвонить по поводу поверки прибора.',
    ],
    'context' => [
        'ip' => '203.0.113.10',
        'userAgent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0',
        'page' => '/contacts/',
    ],
];

$verdict = $endpoint->process($payload);
echo json_encode($verdict, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), PHP_EOL;
