<?php

declare(strict_types=1);

/**
 * Drop-in guard for PHP sites that share the module from /var/www/lib.
 *
 * Add ONE line at the top of the form handler (before the application reads
 * the request):
 *
 *     require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
 *
 * It runs two layers, in order:
 *   1. the WAF (when `waf.enabled` is set in the site config) — inspects the
 *      whole request: URI, query, body, headers, cookies, method and size;
 *   2. the form spam pipeline (off / shadow / enforce).
 *
 * Configuration: config/sites/<host>.php (falls back to default.php, which is
 * "off"). Both layers pass through anything that does not match their config,
 * and any internal error fails open: a broken guard must never take a site down.
 */

require_once dirname(__DIR__) . '/autoload.php';

try {
    $waf = FormSpamChecker\Integration\WafGuard::boot();

    if ($waf->enabled()) {
        $waf->run();
    }
} catch (\Throwable $exception) {
    error_log('[waf] bootstrap failed (fail open): ' . $exception->getMessage());
}

FormSpamChecker\Integration\FormGuard::boot()->run();
