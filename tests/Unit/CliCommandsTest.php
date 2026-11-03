<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use FormSpamChecker\Cli\CheckCommand;
use FormSpamChecker\Cli\TrainCommand;
use FormSpamChecker\Cli\WafCommand;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use stdClass;

/**
 * In-process tests of the CLI command classes.
 *
 * The commands accept injectable output/input closures so their whole logic is
 * covered directly instead of only through child processes.
 */
final class CliCommandsTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    /**
     * @return array{0: CheckCommand, 1: object{out: string, err: string, in: string}}
     */
    private function checkCommand(): array
    {
        $state = new stdClass();
        $state->out = '';
        $state->err = '';
        $state->in = '';

        $command = new CheckCommand(
            function (string $text) use ($state): void {
                $state->out .= $text;
            },
            function (string $text) use ($state): void {
                $state->err .= $text;
            },
            function () use ($state): string {
                return $state->in;
            },
        );

        return [$command, $state];
    }

    private function memoryConfig(): string
    {
        $path = $this->tempDir() . '/config.json';
        file_put_contents($path, json_encode([
            'storage' => ['driver' => 'memory'],
            'cache' => ['driver' => 'memory'],
        ], JSON_THROW_ON_ERROR));

        return $path;
    }

    private function payload(array $fields, string $form = 'contact'): string
    {
        return (string) json_encode([
            'form' => $form,
            'fields' => $fields,
            'context' => ['ip' => '203.0.113.10', 'userAgent' => self::UA],
        ], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public function testCheckCommandCleanAndSpamAndSuspicious(): void
    {
        [$command, $state] = $this->checkCommand();
        $config = $this->memoryConfig();

        self::assertSame(0, $command->run(['spam-check', '--json=' . $this->payload(['name' => 'Иван', 'email' => 'ivan@example.ru']), '--config=' . $config]));
        self::assertStringContainsString('"status":"clean"', $state->out);

        $state->out = '';
        self::assertSame(2, $command->run(['spam-check', '--json=' . $this->payload(['website' => 'filled']), '--config=' . $config]));
        self::assertStringContainsString('"status":"spam"', $state->out);

        $state->out = '';
        self::assertSame(1, $command->run(['spam-check', '--json=' . $this->payload(['message' => 'казино, ставки на спорт, биткоин']), '--config=' . $config]));
        self::assertStringContainsString('"status":"suspicious"', $state->out);
    }

    public function testCheckCommandBase64PositionalPayload(): void
    {
        [$command, $state] = $this->checkCommand();
        $encoded = base64_encode($this->payload(['name' => 'Иван']));

        self::assertSame(0, $command->run(['spam-check', '--config=' . $this->memoryConfig(), '--form=lead', $encoded]));
        self::assertStringContainsString('"form":"lead"', $state->out);
    }

    public function testCheckCommandReadsStdin(): void
    {
        [$command, $state] = $this->checkCommand();
        $state->in = $this->payload(['name' => 'Иван']);

        self::assertSame(0, $command->run(['spam-check', '--stdin', '--config=' . $this->memoryConfig()]));
        self::assertStringContainsString('"status":"clean"', $state->out);
    }

    public function testCheckCommandHelpAndErrors(): void
    {
        [$command, $state] = $this->checkCommand();

        self::assertSame(0, $command->run(['spam-check', '--help']));
        self::assertStringContainsString('Usage: php bin/spam-check', $state->err);

        $state->out = '';
        $state->err = '';
        self::assertSame(3, $command->run(['spam-check', '--nope=1']));
        self::assertStringContainsString('Unknown option', $state->err);

        $state->out = '';
        self::assertSame(3, $command->run(['spam-check', '--json={broken']));
        self::assertStringContainsString('"status":"error"', $state->out);
    }

    private function wafCommand(): array
    {
        $state = new stdClass();
        $state->out = '';
        $state->err = '';
        $state->in = '';

        $command = new WafCommand(
            function (string $text) use ($state): void {
                $state->out .= $text;
            },
            function (string $text) use ($state): void {
                $state->err .= $text;
            },
            function () use ($state): string {
                return $state->in;
            },
        );

        return [$command, $state];
    }

    public function testWafCommandDisabledAllowBlockAndError(): void
    {
        $dir = $this->tempDir();
        $disabled = $dir . '/disabled.json';
        file_put_contents($disabled, '{"waf":{"enabled":false}}');
        $block = $dir . '/block.json';
        file_put_contents($block, '{"waf":{"enabled":true,"mode":"block"}}');

        [$command, $state] = $this->wafCommand();

        self::assertSame(0, $command->run(['waf-check', '--config=' . $disabled, '--json=' . '{"method":"GET","uri":"/"}']));
        self::assertStringContainsString('"status":"disabled"', $state->out);

        $state->out = '';
        $benign = (string) json_encode([
            'method' => 'POST',
            'uri' => '/api/lead',
            'headers' => ['host' => 'example.ru', 'user-agent' => self::UA, 'content-type' => 'application/x-www-form-urlencoded'],
            'body' => 'name=Иван',
        ], JSON_UNESCAPED_UNICODE);
        self::assertSame(0, $command->run(['waf-check', '--config=' . $block, '--json=' . $benign]));
        self::assertStringContainsString('"blocked":false', $state->out);

        $state->out = '';
        self::assertSame(2, $command->run(['waf-check', '--config=' . $block, '--json=' . '{"method":"GET","uri":"/","query":{"q":"1 UNION SELECT x FROM y"},"headers":{"host":"a.ru","user-agent":"Mozilla/5.0"}}']));
        self::assertStringContainsString('"blocked":true', $state->out);

        $state->out = '';
        self::assertSame(3, $command->run(['waf-check', '--json={broken']));
        self::assertStringContainsString('"status":"error"', $state->out);
    }

    public function testWafCommandHelpAndStdin(): void
    {
        [$command, $state] = $this->wafCommand();

        self::assertSame(0, $command->run(['waf-check', '--help']));
        self::assertStringContainsString('Usage: php bin/waf-check', $state->err);

        $state->in = '{"method":"GET","uri":"/","headers":{"host":"a.ru","user-agent":"Mozilla/5.0"}}';
        $config = $this->tempDir() . '/c.json';
        file_put_contents($config, '{"waf":{"enabled":true,"mode":"block"}}');
        self::assertSame(0, $command->run(['waf-check', '--stdin', '--config=' . $config]));
    }

    private function trainCommand(): array
    {
        $state = new stdClass();
        $state->out = '';
        $state->err = '';

        $command = new TrainCommand(
            function (string $text) use ($state): void {
                $state->out .= $text;
            },
            function (string $text) use ($state): void {
                $state->err .= $text;
            },
        );

        return [$command, $state];
    }

    public function testTrainCommandStatsResetAndInlineTraining(): void
    {
        $config = $this->tempDir() . '/train.json';
        file_put_contents($config, json_encode([
            'cache' => ['driver' => 'file', 'path' => $this->tempDir()],
            'bayes' => ['enabled' => true, 'min_documents' => 1],
        ], JSON_THROW_ON_ERROR));

        [$command, $state] = $this->trainCommand();

        self::assertSame(0, $command->run(['spam-train', '--config=' . $config, '--stats']));
        self::assertStringContainsString('"trained":false', $state->out);

        $state->out = '';
        self::assertSame(0, $command->run(['spam-train', '--config=' . $config, '--reset']));
        self::assertStringContainsString('"reset":true', $state->out);

        $state->out = '';
        self::assertSame(0, $command->run([
            'spam-train',
            '--config=' . $config,
            '--text-ham=нужен отчёт по протоколу',
            '--text-spam=casino bitcoin bonus',
        ]));
        self::assertStringContainsString('"persisted":true', $state->out);

        $state->out = '';
        self::assertSame(3, $command->run(['spam-train', '--config=' . $config]));
        self::assertStringContainsString('"error"', $state->out);

        self::assertSame(0, $command->run(['spam-train', '--help']));
        self::assertStringContainsString('Usage: php bin/spam-train', $state->err);
    }

    public function testTrainCommandFileErrors(): void
    {
        $config = $this->tempDir() . '/train.json';
        file_put_contents($config, '{"cache":{"driver":"file","path":"' . str_replace('\\', '\\\\', $this->tempDir()) . '"}}');

        [$command, $state] = $this->trainCommand();

        self::assertSame(3, $command->run(['spam-train', '--config=' . $config, '--ham=' . $this->tempDir() . '/missing.txt']));
        self::assertStringContainsString('not readable', $state->out);
    }
}
