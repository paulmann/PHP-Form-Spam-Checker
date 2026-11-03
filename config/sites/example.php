<?php

declare(strict_types=1);

/**
 * Example per-site configuration for the shared guard.
 *
 * Copy to /var/www/lib/PHP-Form-Spam-Checker/config/sites/<host>.php.
 * Start with mode "shadow" (log only) and switch to "enforce" after reviewing
 * a day of logs. `match` limits the guard to the public form endpoints of the
 * site; `skip` protects admin and authenticated areas.
 */

return [
    'site' => 'example.ru',
    'mode' => 'shadow',
    'form' => 'contact',
    'response' => 'auto',

    // Only these URIs are checked. Empty list = every POST request.
    'match' => [
        '#^/feedback\.php#',
        '#^/api/lead#',
    ],

    // Never checked, even when they match.
    'skip' => [
        '#^/admin#',
        '#^/auth#',
        '#^/login#',
        '#^/cabinet#',
        '#^/api/(?:admin|auth|internal)#',
    ],

    // Full FormSpamChecker\Config array (optional: defaults are used).
    'config' => [
        // Only used by integrations/auto-prepend.php.
        'auto' => false,
        'thresholds' => [
            'suspicious' => 30,
            'spam' => 60,
        ],
        'rate_limit' => [
            'enabled' => true,
            'max' => 8,
            'window' => 900,
        ],
        'keywords' => [
            'enabled' => true,
        ],
        'links' => [
            'enabled' => true,
            'max' => 2,
        ],
        'user_agent' => [
            'enabled' => true,
            'allow_empty' => false,
        ],
    ],
];
