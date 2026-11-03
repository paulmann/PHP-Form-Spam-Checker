<?php

/**
 * PHP CS Fixer configuration for PHP-Form-Spam-Checker 2.0.
 *
 * Baseline is PSR-12 plus PER Coding Style 2.0 (`@PER-CS2x0`; the old alias
 * `@PER-CS2.0` is deprecated in PHP CS Fixer 3.95 and will be removed in 4.0).
 * PER-CS 2.0 is a superset of PSR-12, so `@PSR12` is kept as an explicit,
 * readable statement of intent and `@PER-CS2x0` is applied after it - the
 * later rule set wins on shared keys.
 *
 * Risky rules are whitelisted here (`setRiskyAllowed(true)`) so that
 * `composer cs:check` needs no `--allow-risky` flag in CI.
 *
 * The rules below are idempotent: a second `--dry-run` after `fix` reports
 * zero files. Verify with:
 *
 *     php vendor/bin/php-cs-fixer fix --dry-run --diff
 *     php vendor/bin/php-cs-fixer fix --dry-run --diff   # must be clean
 *
 * Scope: source, tests, CLI entry points, framework integrations, examples,
 * per-site config and the quality tools. `var/`, `vendor/` and `audit/` are
 * generated/third-party and are never touched.
 */

declare(strict_types=1);

$directories = [
    __DIR__ . '/src',
    __DIR__ . '/tests',
    __DIR__ . '/bin',
    __DIR__ . '/integrations',
    __DIR__ . '/examples',
    __DIR__ . '/config',
    __DIR__ . '/tools',
];

$finder = PhpCsFixer\Finder::create()
    // Only scan directories that exist: the tree is mid-rewrite and a missing
    // directory must not turn the gate into a configuration error.
    ->in(array_values(array_filter(
        $directories,
        static fn(string $directory): bool => is_dir($directory),
    )))
    ->exclude(['var', 'vendor', 'audit'])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true)
    // The configuration file itself is part of the gate.
    ->append([__FILE__]);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    // Keep the cache out of the repository: no .gitignore change is needed and
    // CI starts from a cold cache every run.
    ->setCacheFile(sys_get_temp_dir() . '/php-form-spam-checker.php-cs-fixer.cache')
    ->setFinder($finder)
    ->setRules([
        // ---------------------------------------------------------------- sets
        '@PSR12' => true,
        '@PER-CS2x0' => true,
        // PER-CS 2.0 does not ship its own "risky" additions in the set above;
        // enable the risky companion so both halves of PER-CS are enforced.
        '@PER-CS2x0:risky' => true,

        // ------------------------------------------------------- declarations
        'declare_strict_types' => true,
        'nullable_type_declaration_for_default_null_value' => true,

        // ---------------------------------------------------------- imports
        'ordered_imports' => [
            'sort_algorithm' => 'alpha',
            'imports_order' => ['class', 'function', 'const'],
        ],
        'no_unused_imports' => true,
        'global_namespace_import' => [
            // Import classes only: importing functions/constants would collide
            // with `native_function_invocation` below, which prefixes native
            // calls with a leading backslash instead.
            'import_classes' => true,
            'import_constants' => false,
            'import_functions' => false,
        ],
        // Native functions in namespaced code are called as \strlen() so PHP
        // does not fall back to a slower namespace lookup per call.
        'native_function_invocation' => [
            'include' => ['@compiler_optimized'],
            'scope' => 'namespaced',
            'strict' => true,
        ],

        // --------------------------------------------------------- formatting
        'concat_space' => ['spacing' => 'one'],
        'single_line_empty_body' => true,
        'trailing_comma_in_multiline' => [
            'after_heredoc' => true,
            'elements' => ['arguments', 'array_destructuring', 'arrays', 'match', 'parameters'],
        ],

        // ------------------------------------------------------------- phpdoc
        'phpdoc_align' => ['align' => 'vertical'],
        'phpdoc_order' => true,
        'phpdoc_trim' => true,

        // -------------------------------------------------------- risky rules
        'strict_comparison' => true,
        'strict_param' => true,
        'void_return' => true,
        'no_unreachable_default_argument_value' => true,
        'dir_constant' => true,
    ]);
