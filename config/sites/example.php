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
    // Only used by integrations/auto-prepend.php (installed through PHP's
    // auto_prepend_file for sites with many handlers).
    'auto' => false,

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
        // Registry of rejected (unsent) forms: a blocked submission is written
        // here with its full payload so a false positive can be reviewed and
        // replayed with `bin/rejected-forms`. Enabled by default; the derived
        // directory is var/rejected/<site>. It stores personal data on purpose —
        // keep the tree outside the document root.
        'rejected' => [
            'enabled' => true,
            'store_payload' => true,
            'retention_days' => 30,
            'max_records_per_site' => 2000,
            'max_bytes_per_record' => 262144,
            // 'store_files' => false,        // copy uploads for a multipart replay
            // 'capture_suspicious' => false, // also keep "suspicious" (never blocked)
        ],
    ],
];
