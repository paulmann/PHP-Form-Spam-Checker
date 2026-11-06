<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit;

use Closure;
use FormSpamChecker\Cli\RejectedFormsCommand;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Integration\RejectedStore;
use FormSpamChecker\Status;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use stdClass;

/**
 * In-process tests of `bin/rejected-forms`: listing, masked show, dry-run
 * replay, ignore and purge.
 */
final class RejectedFormsCommandTest extends TempDirTestCase
{
    private function state(): stdClass
    {
        $state = new stdClass();
        $state->out = '';
        $state->err = '';

        return $state;
    }

    /**
     * @param (Closure(): array{0: string|false, 1: list<string>})|null $transport
     */
    private function command(stdClass $state, ?Closure $transport = null): RejectedFormsCommand
    {
        return new RejectedFormsCommand(
            function (string $text) use ($state): void {
                $state->out .= $text;
            },
            function (string $text) use ($state): void {
                $state->err .= $text;
            },
            $transport,
        );
    }

    private function config(string $root): Config
    {
        return new Config([
            'storage' => ['driver' => 'file', 'path' => $root . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . 'example.ru'],
            'log' => ['enabled' => false],
        ]);
    }

    private function registryRoot(string $root): string
    {
        return $root . DIRECTORY_SEPARATOR . 'rejected';
    }

    /**
     * @param  array<string, mixed> $fields
     * @param  array<string, mixed> $files
     * @return array<string, mixed>
     */
    private function capture(Config $config, string $name = 'John Smith', array $fields = [], array $files = []): array
    {
        $request = new RequestData(
            fields: $fields !== [] ? $fields : [
                'name' => $name,
                'email' => 'john@example.com',
                'phone' => '+7 999 123-45-67',
                'message' => 'Need a quote',
            ],
            ip: '203.0.113.77',
            headers: [
                'host' => 'example.ru',
                'user-agent' => 'Mozilla/5.0 cli-test',
                'referer' => 'https://example.ru/contact/',
                'origin' => 'https://example.ru',
                'content-type' => 'application/x-www-form-urlencoded',
            ],
            method: 'POST',
            uri: '/contact/',
            formId: 'lead',
        );

        $verdict = new Verdict(Status::Spam, 60, [
            CheckOutcome::suspicious('language', 60, '1 name field(s) contain no Cyrillic letters'),
        ]);

        $record = RejectedStore::capture(
            $request,
            $config,
            $verdict,
            'example.ru',
            'lead',
            RejectedStore::REASON_SPAM,
            ['HTTPS' => 'on', 'HTTP_HOST' => 'example.ru'],
            $files,
        );

        self::assertIsArray($record);

        return $record;
    }

    public function testListShowsTriageColumnsAndJsonForMachines(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));

        $code = $command->run(['rejected-forms', 'list', '--path=' . $this->registryRoot($root)]);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $code);
        self::assertStringContainsString('ID', $state->out);
        self::assertStringContainsString('example.ru', $state->out);
        self::assertStringContainsString('lead', $state->out);
        self::assertStringContainsString('yes', $state->out);
        self::assertStringContainsString('language:', $state->out);
        self::assertStringNotContainsString('john@example.com', $state->out);

        $state->out = '';
        $code = $command->run(['rejected-forms', 'list', '--path=' . $this->registryRoot($root), '--json']);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $code);
        $decoded = json_decode($state->out, true);
        self::assertIsArray($decoded);
        self::assertSame(1, $decoded['count']);
        self::assertSame($record['id'], $decoded['records'][0]['id']);
        self::assertTrue($decoded['records'][0]['has_email']);
    }

    public function testShowIsMaskedByDefaultAndRevealPrintsPersonalData(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $command->run(['rejected-forms', 'show', $record['id'], $path]));
        self::assertStringNotContainsString('john@example.com', $state->out);
        self::assertStringContainsString('[hidden', $state->out);
        self::assertStringContainsString('masked', $state->out);

        $state->out = '';
        self::assertSame(RejectedFormsCommand::EXIT_OK, $command->run(['rejected-forms', 'show', $record['id'], '--reveal', $path]));
        self::assertStringContainsString('john@example.com', $state->out);
        self::assertStringContainsString('shown in full', $state->out);

        $state->out = '';
        self::assertSame(RejectedFormsCommand::EXIT_REFUSED, $command->run(['rejected-forms', 'show', 'nope', $path]));
        self::assertStringContainsString('No record', $state->err);
    }

    public function testReplayDryRunPrintsReasonAndRefusesAnotherHost(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        $code = $command->run(['rejected-forms', 'replay', $record['id'], $path]);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $code);
        self::assertStringContainsString('Dry run', $state->out);
        self::assertStringContainsString('Original rejection: language:', $state->out);
        self::assertStringContainsString('https://example.ru/contact/', $state->out);
        self::assertStringContainsString('--confirm', $state->out);

        $state->out = '';
        $state->err = '';
        $code = $command->run([
            'rejected-forms',
            'replay',
            $record['id'],
            '--url=https://evil.example/contact/',
            $path,
        ]);

        self::assertSame(RejectedFormsCommand::EXIT_REFUSED, $code);
        self::assertStringContainsString('different host', $state->err);

        $state->err = '';
        $code = $command->run([
            'rejected-forms',
            'replay',
            $record['id'],
            '--url=https://evil.example/contact/',
            '--allow-host-change',
            '--json',
            $path,
        ]);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $code);
        $decoded = json_decode($state->out, true);
        self::assertIsArray($decoded);
        self::assertTrue($decoded['dry_run']);
        self::assertSame('https://evil.example/contact/', $decoded['request']['url']);
    }

    public function testReplayRefusesBothModesAndIgnoredRecords(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        self::assertSame(
            RejectedFormsCommand::EXIT_USAGE,
            $command->run(['rejected-forms', 'replay', $record['id'], '--dry-run', '--confirm', $path]),
        );

        $store = new RejectedStore($this->config($root), 'example.ru');
        self::assertTrue($store->ignore($record['id'], 'duplicate'));

        $state->err = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_REFUSED,
            $command->run(['rejected-forms', 'replay', $record['id'], $path]),
        );
        self::assertStringContainsString('ignored', $state->err);
    }

    public function testIgnoreRequiresReasonAndUpdatesStatus(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        self::assertSame(
            RejectedFormsCommand::EXIT_USAGE,
            $command->run(['rejected-forms', 'ignore', $record['id'], $path]),
        );

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'ignore', $record['id'], '--reason=duplicate of ticket 42', $path]),
        );
        self::assertStringContainsString('Ignored', $state->out);

        $store = new RejectedStore($this->config($root), 'example.ru');
        $loaded = $store->find($record['id']);
        self::assertIsArray($loaded);
        self::assertSame('ignored', $loaded['status']);
    }

    public function testPurgeIsDryRunThenDeletesOnlyOldRecords(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $config = $this->config($root);
        $old = $this->capture($config);
        $new = $this->capture($config);

        $store = new RejectedStore($config, 'example.ru');
        touch($store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json', time() - 40 * 86400);
        $path = '--path=' . $this->registryRoot($root);

        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'purge', '--older-than=30', $path]),
        );
        self::assertStringContainsString('Would delete 1 record', $state->out);
        self::assertStringContainsString($old['id'], $state->out);
        self::assertFileExists($store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json');

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'purge', '--older-than=30', '--confirm', $path]),
        );
        self::assertStringContainsString('Deleted 1 record', $state->out);
        self::assertFileDoesNotExist($store->directory() . DIRECTORY_SEPARATOR . $old['id'] . '.json');
        self::assertFileExists($store->directory() . DIRECTORY_SEPARATOR . $new['id'] . '.json');
    }

    public function testShowJsonIsMaskedAndListFiltersWork(): void
    {
        $root = $this->tempDir();
        $state = $this->state();
        $command = $this->command($state);
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $command->run(['rejected-forms', 'show', $record['id'], '--json', $path]));

        $shown = json_decode($state->out, true);
        self::assertIsArray($shown);
        self::assertSame($record['id'], $shown['id']);
        self::assertSame('new', $shown['display_status']);
        self::assertStringContainsString('[hidden', (string) $shown['payload']['fields']['email']);

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'list', '--form=lead', '--since=2020-01-01', '--json', $path]),
        );
        $listed = json_decode($state->out, true);
        self::assertIsArray($listed);
        self::assertSame(1, $listed['count']);

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'list', '--form=other', '--json', $path]),
        );
        $listed = json_decode($state->out, true);
        self::assertIsArray($listed);
        self::assertSame(0, $listed['count']);
    }

    public function testUsageErrorsAndHelp(): void
    {
        $state = $this->state();
        $command = $this->command($state);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $command->run(['rejected-forms', '--help']));
        self::assertStringContainsString('Usage: php bin/rejected-forms', $state->err);

        self::assertSame(RejectedFormsCommand::EXIT_USAGE, $command->run(['rejected-forms', '--nope=1']));
        self::assertSame(RejectedFormsCommand::EXIT_USAGE, $command->run(['rejected-forms', 'bogus']));
        self::assertSame(
            RejectedFormsCommand::EXIT_USAGE,
            $command->run(['rejected-forms', 'list', '--status=zzz']),
        );
        self::assertSame(
            RejectedFormsCommand::EXIT_USAGE,
            $command->run(['rejected-forms', 'list', '--limit=0']),
        );
        self::assertSame(
            RejectedFormsCommand::EXIT_USAGE,
            $command->run(['rejected-forms', 'purge', '--older-than=abc']),
        );
    }

    public function testReplayConfirmSendsThroughTheInjectedTransport(): void
    {
        $root = $this->tempDir();
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        $state = $this->state();
        $command = $this->command($state, static fn(): array => [
            '{"ok":true}',
            ['HTTP/1.1 201 Created', 'Content-Type: application/json'],
        ]);

        $code = $command->run(['rejected-forms', 'replay', $record['id'], '--confirm', '--json', $path]);

        self::assertSame(RejectedFormsCommand::EXIT_OK, $code);
        $decoded = json_decode($state->out, true);
        self::assertIsArray($decoded);
        self::assertFalse($decoded['dry_run']);
        self::assertSame('POST', $decoded['request']['method']);
        self::assertSame(201, $decoded['response']['status']);
        self::assertTrue($decoded['response']['ok']);
        self::assertSame('{"ok":true}', $decoded['response']['body']);

        $store = new RejectedStore($this->config($root), 'example.ru');
        $loaded = $store->find($record['id']);
        self::assertIsArray($loaded);
        self::assertSame('replayed', $loaded['status']);
        self::assertSame(201, $loaded['replay_status']);
    }

    public function testReplayConfirmTransportFailureExitsWithStorageError(): void
    {
        $root = $this->tempDir();
        $record = $this->capture($this->config($root));
        $path = '--path=' . $this->registryRoot($root);

        $state = $this->state();
        $command = $this->command($state, static fn(): array => [false, []]);

        $code = $command->run(['rejected-forms', 'replay', $record['id'], '--confirm', $path]);

        self::assertSame(RejectedFormsCommand::EXIT_ERROR, $code);
        self::assertStringContainsString('replay failed', $state->err);

        $store = new RejectedStore($this->config($root), 'example.ru');
        $loaded = $store->find($record['id']);
        self::assertIsArray($loaded);
        self::assertSame('new', $loaded['status']);
    }

    public function testShowRevealPrintsFilesAndNonStringValues(): void
    {
        $root = $this->tempDir();
        $upload = $this->tempDir() . DIRECTORY_SEPARATOR . 'quote.pdf';
        file_put_contents($upload, 'PDFDATA');

        $config = $this->config($root);
        $record = $this->capture($config, 'John Smith', [
            'name' => 'John Smith',
            'subscribe' => true,
            'callback' => false,
            'nothing' => null,
            'comment' => 'call me',
        ], [
            'document' => [
                'name' => 'quote.pdf',
                'type' => 'application/pdf',
                'tmp_name' => $upload,
                'error' => UPLOAD_ERR_OK,
                'size' => 7,
            ],
        ]);

        $state = $this->state();
        $command = $this->command($state);

        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'show', $record['id'], '--reveal', '--path=' . $this->registryRoot($root)]),
        );
        self::assertStringContainsString('Files (1):', $state->out);
        self::assertStringContainsString('quote.pdf', $state->out);
        self::assertStringContainsString('subscribe = yes', $state->out);
        self::assertStringContainsString('callback = no', $state->out);
        self::assertStringContainsString('nothing = [null]', $state->out);
    }

    public function testConfigFileWithExplicitRejectedPathAndSiteFilter(): void
    {
        $root = $this->tempDir();
        $configFile = $this->tempDir() . DIRECTORY_SEPARATOR . 'site.json';
        $registry = $this->tempDir() . DIRECTORY_SEPARATOR . 'registry-explicit';

        file_put_contents($configFile, json_encode([
            'storage' => ['path' => $root . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . 'example.ru'],
            'rejected' => ['path' => $registry, 'retention_days' => 30],
        ], JSON_THROW_ON_ERROR));

        $config = Config::fromFile($configFile);
        $record = $this->capture($config);

        $state = $this->state();
        $command = $this->command($state);

        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'list', '--config=' . $configFile, '--json']),
        );
        $listed = json_decode($state->out, true);
        self::assertIsArray($listed);
        self::assertSame(1, $listed['count']);
        self::assertSame($record['id'], $listed['records'][0]['id']);

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run([
                'rejected-forms',
                'list',
                '--path=',
                '--site=example.ru',
                '--json',
                '--config=' . $configFile,
            ]),
        );
    }

    public function testPurgeUsesTheConfiguredRetentionWhenOlderThanIsOmitted(): void
    {
        $root = $this->tempDir();
        $configFile = $this->tempDir() . DIRECTORY_SEPARATOR . 'site.json';
        $registry = $this->tempDir() . DIRECTORY_SEPARATOR . 'registry-retention';

        file_put_contents($configFile, json_encode([
            'storage' => ['path' => $root . DIRECTORY_SEPARATOR . 'sites' . DIRECTORY_SEPARATOR . 'example.ru'],
            'rejected' => ['path' => $registry, 'retention_days' => 30],
        ], JSON_THROW_ON_ERROR));

        $config = Config::fromFile($configFile);
        $record = $this->capture($config);
        touch($registry . DIRECTORY_SEPARATOR . $record['id'] . '.json', time() - 40 * 86400);

        $state = $this->state();
        $command = $this->command($state);

        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'purge', '--config=' . $configFile]),
        );
        self::assertStringContainsString('Would delete 1 record', $state->out);

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'purge', '--config=' . $configFile, '--confirm']),
        );
        self::assertStringContainsString('Deleted 1 record', $state->out);
        self::assertFileDoesNotExist($registry . DIRECTORY_SEPARATOR . $record['id'] . '.json');
    }

    public function testEmptyRegistryAndEmptySiteFilter(): void
    {
        $state = $this->state();
        $command = $this->command($state);
        $emptyRoot = $this->tempDir() . DIRECTORY_SEPARATOR . 'empty-registry';

        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'list', '--path=' . $emptyRoot]),
        );
        self::assertStringContainsString('No rejected forms found.', $state->out);

        $state->out = '';
        self::assertSame(
            RejectedFormsCommand::EXIT_OK,
            $command->run(['rejected-forms', 'list', '--path=' . $emptyRoot, '--site=example.ru', '--json']),
        );
        $decoded = json_decode($state->out, true);
        self::assertIsArray($decoded);
        self::assertSame(0, $decoded['count']);
    }
}
