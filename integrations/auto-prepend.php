<?php

declare(strict_types=1);

/**
 * Same guard, installed globally through PHP's auto_prepend_file for sites
 * where editing every handler is impractical.
 *
 * Only sites whose config/sites/<host>.php has `'auto' => true` and matching
 * `match` patterns are checked; everything else passes through untouched.
 * `skip` patterns protect admin panels and authenticated areas.
 *
 * The WAF layer runs first when `waf.enabled` is set, independently of the
 * legacy `auto` flag: a site can protect every request with the firewall and
 * keep the form pipeline limited to its form endpoints.
 */

require_once dirname(__DIR__) . '/autoload.php';

$waf = FormSpamChecker\Integration\WafGuard::boot();

if ($waf->enabled()) {
    $waf->run();
}

$guard = FormSpamChecker\Integration\FormGuard::boot();

if ($guard->config()->bool('auto', false)) {
    $guard->run();
}
