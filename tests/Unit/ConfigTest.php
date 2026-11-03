<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Config;
use FormSpamChecker\Exception\InvalidConfigException;
use FormSpamChecker\Tests\Support\TempDirTestCase;

final class ConfigTest extends TempDirTestCase
{
    public function testDefaultsAreUsableWithoutConfiguration(): void
    {
        $config = new Config();

        self::assertSame(30, $config->int('thresholds.suspicious'));
        self::assertSame(60, $config->int('thresholds.spam'));
        self::assertTrue($config->bool('honeypot.enabled'));
        self::assertSame(['website', '_fs_hp'], $config->array('honeypot.fields'));
        self::assertFalse($config->bool('time_trap.enabled'));
    }

    public function testDotNotationAndFallbacks(): void
    {
        $config = new Config(['thresholds' => ['spam' => 42]]);

        self::assertSame(42, $config->int('thresholds.spam'));
        self::assertSame('fallback', $config->string('missing.key', 'fallback'));
        self::assertNull($config->get('missing.key'));
    }

    public function testScalarCoercion(): void
    {
        $config = new Config([
            'rate_limit' => ['max' => '12', 'enabled' => 'off'],
            'links' => ['max' => 2.9],
        ]);

        self::assertSame(12, $config->int('rate_limit.max'));
        self::assertFalse($config->bool('rate_limit.enabled'));
        self::assertSame(2, $config->int('links.max'));
        self::assertSame(2.9, $config->float('links.max'));
    }

    public function testFormOverrideIsMergedOverGlobals(): void
    {
        $config = new Config([
            'rate_limit' => ['max' => 8],
            'forms' => [
                'register' => ['rate_limit' => ['max' => 3]],
            ],
        ]);

        $register = $config->form('register');

        self::assertSame(3, $register->int('rate_limit.max'));
        self::assertSame(900, $register->int('rate_limit.window'));
        // The root config is not mutated by form().
        self::assertSame(8, $config->int('rate_limit.max'));
    }

    public function testUnknownFormKeepsGlobalValues(): void
    {
        $config = new Config(['rate_limit' => ['max' => 7]]);

        self::assertSame(7, $config->form('unknown')->int('rate_limit.max'));
    }

    public function testListsAreReplacedNotMerged(): void
    {
        $config = new Config([
            'honeypot' => ['fields' => ['custom_hp']],
        ]);

        self::assertSame(['custom_hp'], $config->array('honeypot.fields'));
    }

    public function testExcludedFieldsContainDefaultsAndCustomOnes(): void
    {
        $config = new Config(['fields' => ['exclude' => ['my_token']]]);
        $excluded = $config->excludedFields();

        self::assertContains('website', $excluded);
        self::assertContains('_fs_ts', $excluded);
        self::assertContains('my_token', $excluded);
        self::assertSame(array_values(array_unique($excluded)), $excluded);
    }

    public function testSecretRequiresEnoughEntropy(): void
    {
        $config = new Config(['time_trap' => ['secret' => 'short']]);

        $this->expectException(InvalidConfigException::class);
        $config->secret();
    }

    public function testSecretIsReturnedWhenStrongEnough(): void
    {
        $config = new Config(['time_trap' => ['secret' => '0123456789abcdef']]);

        self::assertSame('0123456789abcdef', $config->secret());
    }

    public function testStoragePathFallsBackToTempDirectory(): void
    {
        $config = new Config();

        self::assertStringContainsString('php-form-spam-checker', $config->storagePath());
    }

    public function testStoragePathCanBeConfigured(): void
    {
        $dir = $this->tempDir();
        $config = new Config(['storage' => ['path' => $dir . DIRECTORY_SEPARATOR]]);

        self::assertSame($dir, $config->storagePath());
    }

    public function testFromFileUnwrapsSharedGuardSiteConfiguration(): void
    {
        $file = $this->tempDir() . DIRECTORY_SEPARATOR . 'site.php';
        file_put_contents(
            $file,
            "<?php return [\n"
            . "    'site' => 'example.ru',\n"
            . "    'mode' => 'enforce',\n"
            . "    'match' => ['#^/form\\.php#'],\n"
            . "    'config' => [\n"
            . "        'thresholds' => ['spam' => 45],\n"
            . "        'log' => ['enabled' => true, 'path' => '/tmp/x.jsonl'],\n"
            . "        'storage' => ['driver' => 'memory'],\n"
            . "    ],\n"
            . "];\n",
        );

        $config = Config::fromFile($file);

        self::assertSame(45, $config->int('thresholds.spam'));
        self::assertTrue($config->bool('log.enabled'));
        self::assertSame('/tmp/x.jsonl', $config->string('log.path'));
        // Defaults still apply underneath the unwrapped site config.
        self::assertSame(8, $config->int('rate_limit.max'));
    }

    public function testPlainConfigurationWithConfigKeyIsNotUnwrapped(): void
    {
        $file = $this->tempDir() . DIRECTORY_SEPARATOR . 'plain.php';
        file_put_contents($file, "<?php return ['thresholds' => ['spam' => 50], 'config' => ['x' => 1]];\n");

        $config = Config::fromFile($file);

        self::assertSame(50, $config->int('thresholds.spam'));
    }

    public function testFromFileLoadsPhpArray(): void
    {
        $file = $this->tempDir() . DIRECTORY_SEPARATOR . 'config.php';
        file_put_contents($file, "<?php return ['thresholds' => ['spam' => 55]];\n");

        $config = Config::fromFile($file);

        self::assertSame(55, $config->int('thresholds.spam'));
    }

    public function testFromFileLoadsJson(): void
    {
        $file = $this->tempDir() . DIRECTORY_SEPARATOR . 'config.json';
        file_put_contents($file, '{"thresholds":{"spam":45}}');

        self::assertSame(45, Config::fromFile($file)->int('thresholds.spam'));
    }

    public function testFromFileRejectsBrokenJson(): void
    {
        $file = $this->tempDir() . DIRECTORY_SEPARATOR . 'broken.json';
        file_put_contents($file, '{"thresholds":');

        $this->expectException(InvalidConfigException::class);
        Config::fromFile($file);
    }

    public function testFromFileRejectsMissingFile(): void
    {
        $this->expectException(InvalidConfigException::class);
        Config::fromFile($this->tempDir() . '/nope.php');
    }

    public function testWithReturnsNewInstance(): void
    {
        $config = new Config();
        $changed = $config->with(['thresholds' => ['spam' => 10]]);

        self::assertSame(60, $config->int('thresholds.spam'));
        self::assertSame(10, $changed->int('thresholds.spam'));
    }

    public function testToArrayReturnsEffectiveConfiguration(): void
    {
        $config = new Config(['thresholds' => ['spam' => 33]]);
        $array = $config->toArray();

        self::assertSame(33, $array['thresholds']['spam']);
        self::assertArrayHasKey('honeypot', $array);
    }
}
