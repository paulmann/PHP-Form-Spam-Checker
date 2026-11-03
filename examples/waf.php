<?php

declare(strict_types=1);

/**
 * WAF — drop-in `auto_prepend_file` example.
 *
 * PRODUCTION USE — one of these, before the application handles the request:
 *
 *   1) Per site, one line in the front controller:
 *
 *        require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
 *
 *   2) Globally for a PHP-FPM pool (runs on every PHP request):
 *
 *        php_admin_value[auto_prepend_file] = \
 *            /var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php
 *
 * The real drop-in is `integrations/waf.php`; it reads
 * `config/sites/<host>.php` (the `waf` section, plus optional `waf_mode`,
 * `waf_skip`, `waf_match`, `waf_response`) and fails open on any error.
 *
 * THIS FILE is the library-level example: run it from the console to see what
 * the same rules answer for a synthetic request, without touching a live site.
 * Use it on a local or staging copy only.
 *
 * Run:  php examples/waf.php
 *       php examples/waf.php "/api/lead?q=1%27+OR+1%3D1"
 */

use FormSpamChecker\Config;
use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafRequest;

require dirname(__DIR__) . '/autoload.php';

// ---------------------------------------------------------------------------
// 1. Configuration: the same section a site config would carry.
// ---------------------------------------------------------------------------
$config = Config::fromArray([
    'waf' => [
        'enabled' => true,
        'mode' => 'monitor',          // off | monitor | block (block is the guard's job)
        'block_status' => 403,
        'max_body_bytes' => 1048576,
        'thresholds' => ['block' => 60, 'suspicious' => 30],
        'rules' => [
            'sql_injection' => true,
            'xss' => true,
            'path_traversal' => true,
            'command_injection' => true,
            'scanner' => true,
            'header_injection' => true,
            'protocol' => true,
            // Optional rules need injected collaborators; see the docs.
            'ip_reputation' => false,
            'rate_limit' => false,
        ],
    ],
]);

// ---------------------------------------------------------------------------
// 2. A request snapshot. In a real site use WafRequest::fromGlobals().
// ---------------------------------------------------------------------------
$uri = $argv[1] ?? '/feedback.php';

$request = new WafRequest(
    method: 'POST',
    uri: $uri,
    ip: '203.0.113.10',
    // Body-carrying requests should carry host + content-type: the protocol
    // rule scores their absence (softly) and a CLI caller often forgets them.
    headers: [
        'host' => 'example.ru',
        'content-type' => 'application/x-www-form-urlencoded',
        'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    ],
    cookies: [],
    query: [],
    fields: ['message' => 'Нужен отчёт по поверке прибора.'],
    now: time(),
    formId: 'contact',
);

// ---------------------------------------------------------------------------
// 3. Run every rule and aggregate. The WAF has no opinion about HTTP: the
//    guard (integrations/waf.php) turns "blocked" into a response in block mode.
// ---------------------------------------------------------------------------
$waf = Waf::withDefaultRules($config, null, null, new ErrorLogLogger('waf-example'));
$verdict = $waf->inspect($request);

$result = [
    'uri' => $uri,
    'blocked' => $verdict->isBlocked(),
    'status' => $verdict->status,
    'score' => $verdict->score,
    'reasons' => $verdict->reasons(),
    'findings' => array_map(
        static fn($finding): array => $finding->toArray(),
        $verdict->findings,
    ),
];

echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), PHP_EOL;

exit($verdict->isBlocked() ? 2 : 0);
