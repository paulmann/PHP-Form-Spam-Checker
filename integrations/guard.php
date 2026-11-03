<?php

declare(strict_types=1);

/**
 * Drop-in form guard for PHP sites that share the module from /var/www/lib.
 *
 * Add ONE line at the top of the form handler (before the application reads
 * the request):
 *
 *     require '/var/www/lib/PHP-Form-Spam-Checker/integrations/guard.php';
 *
 * Configuration: config/sites/<host>.php (falls back to default.php, which is
 * "off"). The guard only runs for POST requests matching that configuration.
 */

require_once dirname(__DIR__) . '/autoload.php';

FormSpamChecker\Integration\FormGuard::boot()->run();
