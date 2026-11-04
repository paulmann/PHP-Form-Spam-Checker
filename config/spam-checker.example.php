<?php

declare(strict_types=1);

/**
 * Example configuration — copy to config/spam-checker.php and edit.
 *
 * Every value is optional: the library ships safe defaults (see
 * FormSpamChecker\Config::defaults()). Values shown here are the defaults
 * unless marked otherwise.
 */

return [
    // Overall verdict thresholds: the capped sum of check scores.
    'thresholds' => [
        'suspicious' => 30,
        'spam' => 60,
    ],

    // Signed time trap. REQUIRED for the FormProtector->fields() helper.
    'time_trap' => [
        'enabled' => true,
        // Use a long random string from the environment, never commit it.
        'secret' => getenv('SPAM_CHECKER_SECRET') ?: 'CHANGE-ME-at-least-16-random-characters',
        'min_seconds' => 2,
        'max_seconds' => 604800, // 7 days: cached pages stay usable
    ],

    // Durable rate limiting per IP + form.
    'rate_limit' => [
        'enabled' => true,
        'max' => 8,
        'window' => 900,
    ],

    // Keyword scoring. Add project-specific words here.
    'keywords' => [
        'enabled' => true,
        'words' => [
            'казино', 'ставки на спорт', 'заработок без вложений', 'криптовалюта',
            'bitcoin', 'casino', 'betting', 'backlinks',
        ],
    ],

    'links' => [
        'enabled' => true,
        'max' => 2,
    ],

    'email' => [
        'enabled' => true,
        // Reject throwaway mailboxes before a human ever sees the lead.
        'disposable_score' => 70,
        'disposable_domains' => [],
    ],

    // Language heuristics: mixed-script scoring and the optional Cyrillic
    // requirement. Both are disabled by default and are opt-in per site.
    'language' => [
        'enabled' => false,
        'require_cyrillic' => false,
        // Russian-language form: require a Cyrillic letter in name-like fields.
        // 60 makes a Latin-only name alone reach the spam threshold; 40 keeps it
        // at "suspicious". Leave the section disabled unless the site needs it.
        // 'missing_score' => 60,
    ],

    // File storage: the default works on shared hosting without Redis.
    'storage' => [
        'driver' => 'file',
        'path' => dirname(__DIR__) . '/var/storage',
    ],

    // Verdict log: one JSON line per submission (PII off by default).
    'log' => [
        'enabled' => true,
        'path' => dirname(__DIR__) . '/var/log/verdicts.jsonl',
        'pii' => false,
    ],

    // HTTP bridge (public/check.php): require a shared key when exposed.
    'endpoint' => [
        'key' => getenv('SPAM_CHECKER_KEY') ?: '',
    ],

    // Per-form overrides. A form id is passed to SpamChecker::check().
    'forms' => [
        'register' => [
            'rate_limit' => ['max' => 3, 'window' => 900],
            'links' => ['max' => 0],
        ],
        'contact' => [
            'time_trap' => ['enabled' => false],
        ],
    ],
];
