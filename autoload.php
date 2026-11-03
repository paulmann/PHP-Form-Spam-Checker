<?php

declare(strict_types=1);

/**
 * Autoloader that works with and without Composer.
 *
 * The deployed checker is often copied as plain files (e.g. consumed by a
 * non-PHP back end through the CLI bridge), so it must not require `vendor/`.
 * PSR-4 mapping is identical to composer.json.
 */

$vendor = __DIR__ . '/vendor/autoload.php';

if (is_file($vendor)) {
    require $vendor;

    return;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'FormSpamChecker\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($file)) {
        require $file;
    }
});
