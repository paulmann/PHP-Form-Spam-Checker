<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Support;

use PHPUnit\Framework\TestCase;

/**
 * Base test case with a temporary directory that is removed after each test.
 */
abstract class TempDirTestCase extends TestCase
{
    /**
     * @var list<string>
     */
    private array $tempDirs = [];

    protected function tempDir(): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'php-form-spam-checker-test-' . bin2hex(random_bytes(8));

        if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
            self::fail('Cannot create temporary directory: ' . $dir);
        }

        $this->tempDirs[] = $dir;

        return $dir;
    }

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $dir) {
            $this->removeDirectory($dir);
        }

        $this->tempDirs = [];

        parent::tearDown();
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $entries = scandir($dir);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                @unlink($path);
            }
        }

        @rmdir($dir);
    }
}
