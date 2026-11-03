<?php

declare(strict_types=1);

/**
 * Same guard, installed globally through PHP's auto_prepend_file for sites
 * where editing every handler is impractical.
 *
 * Only sites whose config/sites/<host>.php has `'auto' => true` and matching
 * `match` patterns are checked; everything else passes through untouched.
 * `skip` patterns protect admin panels and authenticated areas.
 */

require_once dirname(__DIR__) . '/autoload.php';

$guard = FormSpamChecker\Integration\FormGuard::boot();

if ($guard->config()->bool('auto', false)) {
    $guard->run();
}
