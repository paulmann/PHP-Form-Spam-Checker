<?php

declare(strict_types=1);

/**
 * Drop-in HTTP firewall for PHP sites that share the module from /var/www/lib.
 *
 * Add ONE line before the application handles the request:
 *
 *     require '/var/www/lib/PHP-Form-Spam-Checker/integrations/waf.php';
 *
 * Configuration: config/sites/<host>.php (the same file as integrations/guard.php,
 * `waf` section inside `config`, plus optional top-level `waf_mode`, `waf_skip`,
 * `waf_match` and `waf_response`). The default configuration is "off".
 */

require_once dirname(__DIR__) . '/autoload.php';

FormSpamChecker\Integration\WafGuard::boot()->run();
