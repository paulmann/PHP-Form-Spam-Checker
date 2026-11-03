<?php

declare(strict_types=1);

/**
 * AbuseIPDB wiring example: configuration + checker + how to read the result.
 *
 * Run:  php examples/abuseipdb.php
 *       php examples/abuseipdb.php 203.0.113.10
 *
 * Without ABUSEIPDB_KEY (and without ext-curl) the check does not make a
 * network call: it returns `uncertain` and contributes nothing. That is the
 * default fail-open behaviour — this example always works offline.
 *
 * Live lookups need:
 *   - ext-curl,
 *   - a key from https://www.abuseipdb.com (API page), exported as
 *     ABUSEIPDB_KEY (never committed to a repository).
 *
 * Demo only: run it on a local or staging copy. It writes to the system temp
 * directory; do not point it at a production config or state directory.
 */

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\SpamChecker;

require dirname(__DIR__) . '/autoload.php';

$ip = $argv[1] ?? '8.8.8.8';

$stateDir = sys_get_temp_dir() . '/php-form-spam-checker-abuseipdb';

$config = Config::fromArray([
    'thresholds' => [
        'suspicious' => 30,
        'spam' => 60,
    ],

    // ------------------------------------------------------------------
    // AbuseIPDB: disabled by default, enabled here from the environment.
    // ------------------------------------------------------------------
    'abuseipdb' => [
        'enabled' => true,
        'api_key' => getenv('ABUSEIPDB_KEY') ?: '',
        'threshold' => 90,       // abuseConfidenceScore >= 90 -> hard spam
        'cache_ttl' => 21600,    // 6 h per-IP cache; a burst costs one query
        'timeout' => 2.0,        // HTTP timeout, seconds
        'max_age_days' => 30,    // only reports newer than 30 days
        'fail_open' => true,     // lookup failure -> uncertain (contributes 0)
        'circuit_breaker' => [
            'failures' => 3,     // consecutive transport/5xx failures
            'cooldown' => 300,   // seconds the breaker stays open
        ],
    ],

    // The cache stores the per-IP outcome, the 429 back-off and the breaker
    // state. Files are fine on shared hosting; 'memory' works for tests.
    'cache' => [
        'driver' => 'file',
        'path' => $stateDir . '/cache',
    ],
    'storage' => [
        'driver' => 'file',
        'path' => $stateDir,
    ],

    // Keep the rest of the pipeline quiet for the demo.
    'rate_limit' => ['enabled' => false],
    'honeypot' => ['enabled' => false],
    'time_trap' => ['enabled' => false],
    'behavioral' => ['honeypot' => ['dynamic' => false]],
    'log' => ['enabled' => false],
]);

// SpamChecker builds the pipeline, including AbuseIpdbCheck, because
// abuseipdb.enabled is true. The default CurlClient (ext-curl) and the file
// cache above are used for transport and caching.
$checker = new SpamChecker($config);

$request = new RequestData(
    fields: ['message' => 'Нужен отчёт по поверке прибора.'],
    ip: $ip,
    headers: ['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'],
    formId: 'contact',
);

$verdict = $checker->checkRequest($request);

// The outcome of one check can be read from the verdict, which keeps every
// executed check with its evidence.
$abuse = null;
foreach ($verdict->outcomes as $outcome) {
    if ($outcome->check === 'abuseipdb') {
        $abuse = $outcome;
        break;
    }
}

echo "ip:            $ip\n";
echo "verdict:       {$verdict->status->value} (score {$verdict->score})\n";

if ($abuse === null) {
    echo "abuseipdb:     not executed\n";
} else {
    echo "abuseipdb:     {$abuse->status->value} (score {$abuse->score})\n";
    echo "reason:        {$abuse->reason}\n";
}

if (getenv('ABUSEIPDB_KEY') === '') {
    echo "\nABUSEIPDB_KEY is not set: the check is disabled at runtime and no\n";
    echo "network request was made. Export the key to try a live lookup.\n";
}

// How to gate a form on the verdict (the usual integration):
//
//     if ($verdict->isSpam()) {
//         http_response_code(400);
//         exit('Заявка отклонена антиспам-проверкой.');
//     }
