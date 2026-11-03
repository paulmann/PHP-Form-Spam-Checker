<?php

declare(strict_types=1);

/**
 * Fallback configuration: every site without its own file is left untouched.
 *
 * Copy to config/sites/<host>.php and set mode to "shadow" first.
 */

return [
    'site' => 'default',
    'mode' => 'off',
];
