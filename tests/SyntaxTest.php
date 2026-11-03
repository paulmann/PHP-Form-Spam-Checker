<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests;

use FilesystemIterator;
use ParseError;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Parses every PHP file in the repository with TOKEN_PARSE, which is the
 * in-process equivalent of `php -l`: a syntax error anywhere fails the build.
 */
final class SyntaxTest extends TestCase
{
    public function testEveryPhpFileParses(): void
    {
        $root = \dirname(__DIR__);
        $files = [];

        foreach (['src', 'tests', 'examples', 'config', 'public'] as $dir) {
            $files = [...$files, ...$this->phpFiles($root . DIRECTORY_SEPARATOR . $dir)];
        }

        $files[] = $root . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'spam-check';
        $files[] = $root . DIRECTORY_SEPARATOR . 'autoload.php';

        self::assertNotEmpty($files);

        foreach ($files as $file) {
            $code = file_get_contents($file);
            self::assertIsString($code, 'Cannot read ' . $file);

            try {
                token_get_all($code, TOKEN_PARSE);
            } catch (ParseError $exception) {
                self::fail(\sprintf('Syntax error in %s: %s', $file, $exception->getMessage()));
            }
        }
    }

    /**
     * @return list<string>
     */
    private function phpFiles(string $dir): array
    {
        if (!is_dir($dir)) {
            return [];
        }

        $result = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $result[] = $file->getPathname();
            }
        }

        sort($result);

        return $result;
    }
}
