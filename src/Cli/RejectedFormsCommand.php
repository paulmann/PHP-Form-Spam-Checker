<?php

declare(strict_types=1);

namespace FormSpamChecker\Cli;

use Closure;
use FormSpamChecker\Config;
use FormSpamChecker\Integration\RejectedStore;
use FormSpamChecker\Integration\ReplayRequest;
use InvalidArgumentException;
use Throwable;

/**
 * CLI bridge for the registry of rejected (unsent) form submissions.
 *
 * The registry lives next to the drop-in guard and is written by it; this
 * command is how an operator reads it, turns a false positive back into a real
 * submission and prunes what is no longer needed.
 *
 * Usage:
 *   php bin/rejected-forms list [--site=SITE] [--form=FORM] [--status=STATUS]
 *                               [--since=YYYY-MM-DD|EPOCH] [--limit=N] [--json]
 *   php bin/rejected-forms show <id> [--reveal] [--json]
 *   php bin/rejected-forms replay <id> [--url=URL] [--dry-run | --confirm]
 *                               [--allow-host-change] [--json]
 *   php bin/rejected-forms ignore <id> --reason=TEXT [--json]
 *   php bin/rejected-forms purge [--older-than=DAYS] [--confirm] [--json]
 *
 * Every command accepts `--config=PATH` (or SPAM_CHECKER_CONFIG),
 * `--path=REGISTRY_ROOT` and `--site=SITE`. Without them the root is the
 * shared guard's `var/rejected`.
 *
 * Personal data is shown masked unless `--reveal` is passed on purpose; replay
 * is a dry run unless `--confirm` is passed, and never goes to a different host
 * without `--allow-host-change`.
 *
 * Exit codes: 0 success; 1 record or operation refused (unknown id, different
 * host, ignored record); 2 usage error; 3 storage or transport error.
 */
final class RejectedFormsCommand
{
    public const int EXIT_OK = 0;
    public const int EXIT_REFUSED = 1;
    public const int EXIT_USAGE = 2;
    public const int EXIT_ERROR = 3;

    /**
     * Flags that take no value.
     *
     * @var list<string>
     */
    private const array FLAGS = ['help', 'json', 'reveal', 'dry-run', 'confirm', 'allow-host-change'];

    /**
     * Options that require `--name=value`.
     *
     * @var list<string>
     */
    private const array VALUE_OPTIONS = [
        'config', 'path', 'site', 'form', 'status', 'since', 'limit', 'url', 'reason', 'older-than',
    ];

    /** @var Closure(string): void */
    private readonly Closure $out;

    /** @var Closure(string): void */
    private readonly Closure $err;

    /** @var (Closure(): array{0: string|false, 1: list<string>})|null */
    private readonly ?Closure $transport;

    /**
     * Streams are injectable so the command is testable in-process; the replay
     * transport is injectable for the same reason (no network in tests).
     *
     * @param Closure(string): void|null                                $out
     * @param Closure(string): void|null                                $err
     * @param (Closure(): array{0: string|false, 1: list<string>})|null $transport
     */
    public function __construct(?Closure $out = null, ?Closure $err = null, ?Closure $transport = null)
    {
        $this->out = $out ?? static function (string $text): void {
            fwrite(STDOUT, $text);
        };
        $this->err = $err ?? static function (string $text): void {
            fwrite(STDERR, $text);
        };
        $this->transport = $transport;
    }

    /**
     * @param list<string> $argv raw argv (index 0 is the script name)
     */
    public function run(array $argv): int
    {
        try {
            $parsed = $this->parse(\array_slice($argv, 1));
            $options = $parsed['options'];

            if (($options['help'] ?? false) === true) {
                ($this->err)(self::usage());

                return self::EXIT_OK;
            }

            return match ($parsed['command']) {
                'list' => $this->listCommand($options),
                'show' => $this->showCommand($parsed['id'], $options),
                'replay' => $this->replayCommand($parsed['id'], $options),
                'ignore' => $this->ignoreCommand($parsed['id'], $options),
                'purge' => $this->purgeCommand($options),
            };
        } catch (InvalidArgumentException $exception) {
            ($this->err)('rejected-forms: ' . $exception->getMessage() . PHP_EOL . PHP_EOL . self::usage());

            return self::EXIT_USAGE;
        } catch (Throwable $exception) {
            ($this->err)('rejected-forms: ' . $exception->getMessage() . PHP_EOL);

            return self::EXIT_ERROR;
        }
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function listCommand(array $options): int
    {
        $context = $this->context($options);
        $filters = [];

        $status = $this->optionString($options, 'status');

        if ($status !== '') {
            if (!\in_array($status, RejectedStore::statuses(), true)) {
                throw new InvalidArgumentException(
                    'Unknown --status "' . $status . '"; expected one of: ' . implode(', ', RejectedStore::statuses()) . '.',
                );
            }

            $filters['status'] = $status;
        }

        $form = $this->optionString($options, 'form');

        if ($form !== '') {
            $filters['form'] = $form;
        }

        $since = $this->optionString($options, 'since');

        if ($since !== '') {
            $filters['since'] = $this->parseSince($since);
        }

        $limit = $this->parseLimit($options, 200);
        $filters['limit'] = $limit;

        $summaries = [];

        foreach ($this->stores($context, $options) as $store) {
            foreach ($store->listRecords($filters) as $record) {
                $summaries[] = $store->summarize($record);
            }
        }

        usort(
            $summaries,
            static fn(array $a, array $b): int => [$b['ts_utc'], $b['id']] <=> [$a['ts_utc'], $a['id']],
        );

        $summaries = \array_slice($summaries, 0, $limit);

        if (($options['json'] ?? false) === true) {
            $this->emitJson(['count' => \count($summaries), 'records' => $summaries]);

            return self::EXIT_OK;
        }

        if ($summaries === []) {
            $this->emit('No rejected forms found.' . PHP_EOL);

            return self::EXIT_OK;
        }

        $this->emit($this->formatTable($summaries));

        return self::EXIT_OK;
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function showCommand(string $id, array $options): int
    {
        if ($id === '') {
            throw new InvalidArgumentException('show requires a record id: php bin/rejected-forms show <id>');
        }

        $context = $this->context($options);
        $found = $this->findRecord($context, $options, $id);

        if ($found === null) {
            return $this->refuse('No record with id "' . $id . '".');
        }

        [$store, $record] = $found;
        $reveal = ($options['reveal'] ?? false) === true;
        $view = $reveal ? $record : RejectedStore::maskRecord($record);
        $view['display_status'] = $store->effectiveStatus($record);

        if (($options['json'] ?? false) === true) {
            $this->emitJson($view);

            return self::EXIT_OK;
        }

        $this->emit($this->formatRecord($view, $reveal));

        return self::EXIT_OK;
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function replayCommand(string $id, array $options): int
    {
        if ($id === '') {
            throw new InvalidArgumentException('replay requires a record id: php bin/rejected-forms replay <id>');
        }

        $dryRun = ($options['dry-run'] ?? false) === true;
        $confirm = ($options['confirm'] ?? false) === true;

        if ($dryRun && $confirm) {
            throw new InvalidArgumentException('--dry-run and --confirm are mutually exclusive.');
        }

        $context = $this->context($options);
        $found = $this->findRecord($context, $options, $id);

        if ($found === null) {
            return $this->refuse('No record with id "' . $id . '".');
        }

        [$store, $record] = $found;

        if (($record['status'] ?? '') === RejectedStore::STATUS_IGNORED) {
            return $this->refuse('Record "' . $id . '" is ignored; un-ignore it before replaying.');
        }

        $url = $this->optionString($options, 'url');
        $allowHostChange = ($options['allow-host-change'] ?? false) === true;
        $refusal = ReplayRequest::checkTarget($record, $url !== '' ? $url : null, $allowHostChange);

        if ($refusal !== null) {
            return $this->refuse($refusal);
        }

        $reasons = RejectedStore::reasons($record);

        try {
            $request = ReplayRequest::fromRecord($record, $url !== '' ? $url : null, $store->directory());
        } catch (InvalidArgumentException $exception) {
            return $this->refuse($exception->getMessage());
        }

        if (!$confirm) {
            if (($options['json'] ?? false) === true) {
                $this->emitJson([
                    'dry_run' => true,
                    'id' => $id,
                    'reasons' => $reasons,
                    'request' => $request->preview(),
                ]);

                return self::EXIT_OK;
            }

            $this->emit($this->formatPreview($request->preview(), $reasons));

            return self::EXIT_OK;
        }

        $result = $request->send(10.0, $this->transport);

        $httpStatus = $result['status'];

        if ($httpStatus === 0) {
            ($this->err)(
                'rejected-forms: replay failed: ' . $result['error'] . PHP_EOL,
            );

            return self::EXIT_ERROR;
        }

        $store->markReplayed($id, $request->url, $httpStatus);

        if (($options['json'] ?? false) === true) {
            $this->emitJson([
                'dry_run' => false,
                'id' => $id,
                'reasons' => $reasons,
                'request' => $request->toArray(),
                'response' => $result,
            ]);

            return self::EXIT_OK;
        }

        $this->emit(\sprintf(
            'Replayed %s -> HTTP %d%s' . PHP_EOL . 'Original rejection: %s' . PHP_EOL . 'Response body: %s' . PHP_EOL,
            $id,
            $httpStatus,
            $result['ok'] === true ? '' : ' (non-2xx/3xx)',
            implode('; ', $reasons),
            $result['body'],
        ));

        return self::EXIT_OK;
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function ignoreCommand(string $id, array $options): int
    {
        if ($id === '') {
            throw new InvalidArgumentException('ignore requires a record id: php bin/rejected-forms ignore <id> --reason=TEXT');
        }

        $reason = trim($this->optionString($options, 'reason'));

        if ($reason === '') {
            throw new InvalidArgumentException('ignore requires --reason=TEXT (recorded in the registry).');
        }

        $context = $this->context($options);
        $found = $this->findRecord($context, $options, $id);

        if ($found === null) {
            return $this->refuse('No record with id "' . $id . '".');
        }

        [$store] = $found;

        if (!$store->ignore($id, $reason)) {
            return $this->refuse('Could not update record "' . $id . '".');
        }

        if (($options['json'] ?? false) === true) {
            $this->emitJson(['id' => $id, 'status' => RejectedStore::STATUS_IGNORED, 'reason' => $reason]);

            return self::EXIT_OK;
        }

        $this->emit('Ignored ' . $id . ': ' . $reason . PHP_EOL);

        return self::EXIT_OK;
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function purgeCommand(array $options): int
    {
        $context = $this->context($options);
        $olderThanRaw = $this->optionString($options, 'older-than');
        $olderThan = $olderThanRaw !== ''
            ? $this->parseDays($olderThanRaw)
            : max(0, $context['config']->int('rejected.retention_days', 30));
        $confirm = ($options['confirm'] ?? false) === true;

        $ids = [];

        foreach ($this->stores($context, $options) as $store) {
            $ids = [...$ids, ...$store->purgeCandidates($olderThan)];
        }

        sort($ids);

        if (!$confirm) {
            if (($options['json'] ?? false) === true) {
                $this->emitJson([
                    'dry_run' => true,
                    'older_than_days' => $olderThan,
                    'count' => \count($ids),
                    'ids' => $ids,
                ]);

                return self::EXIT_OK;
            }

            if ($ids === []) {
                $this->emit(\sprintf('Nothing to purge (older than %d day(s)).' . PHP_EOL, $olderThan));

                return self::EXIT_OK;
            }

            $this->emit(\sprintf(
                'Would delete %d record(s) older than %d day(s) (dry run, add --confirm to delete):' . PHP_EOL,
                \count($ids),
                $olderThan,
            ));

            foreach ($ids as $id) {
                $this->emit('  ' . $id . PHP_EOL);
            }

            return self::EXIT_OK;
        }

        $deleted = [];

        foreach ($this->stores($context, $options) as $store) {
            $deleted = [...$deleted, ...$store->purge($olderThan)];
        }

        sort($deleted);

        if (($options['json'] ?? false) === true) {
            $this->emitJson([
                'dry_run' => false,
                'older_than_days' => $olderThan,
                'count' => \count($deleted),
                'ids' => $deleted,
            ]);

            return self::EXIT_OK;
        }

        $this->emit(\sprintf('Deleted %d record(s) older than %d day(s).' . PHP_EOL, \count($deleted), $olderThan));

        return self::EXIT_OK;
    }

    /**
     * @param  array<string, string|bool>                            $options
     * @return array{config: Config, root: string, explicit: string}
     */
    private function context(array $options): array
    {
        $configPath = $this->optionString($options, 'config');

        if ($configPath === '') {
            $environmentPath = getenv('SPAM_CHECKER_CONFIG');
            $configPath = \is_string($environmentPath) ? $environmentPath : '';
        }

        $config = $configPath !== '' ? Config::fromFile($configPath) : new Config();
        $explicit = rtrim($config->string('rejected.path'), '/\\');
        $root = rtrim($this->optionString($options, 'path'), '/\\');

        if ($root === '') {
            if ($explicit !== '') {
                $root = \dirname($explicit);
            } else {
                $storage = rtrim($config->string('storage.path'), '/\\');
                $root = $storage !== ''
                    ? \dirname(\dirname($storage)) . DIRECTORY_SEPARATOR . 'rejected'
                    : \dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'rejected';
            }
        }

        return ['config' => $config, 'root' => $root, 'explicit' => $explicit];
    }

    /**
     * @param  array{config: Config, root: string, explicit: string} $context
     * @param  array<string, string|bool>                            $options
     * @return list<RejectedStore>
     */
    private function stores(array $context, array $options): array
    {
        $config = $context['config'];
        $site = $this->optionString($options, 'site');

        if ($context['explicit'] !== '') {
            return [new RejectedStore($config, $site !== '' ? $site : basename($context['explicit']), $context['explicit'])];
        }

        if ($site !== '') {
            return [new RejectedStore($config, $site, $context['root'] . DIRECTORY_SEPARATOR . self::slug($site))];
        }

        $stores = [];
        $entries = @scandir($context['root']);

        if ($entries !== false) {
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
                    continue;
                }

                if (is_dir($context['root'] . DIRECTORY_SEPARATOR . $entry)) {
                    $stores[] = new RejectedStore($config, $entry, $context['root'] . DIRECTORY_SEPARATOR . $entry);
                }
            }
        }

        return $stores;
    }

    /**
     * @param  array{config: Config, root: string, explicit: string} $context
     * @param  array<string, string|bool>                            $options
     * @return array{0: RejectedStore, 1: array<string, mixed>}|null
     */
    private function findRecord(array $context, array $options, string $id): ?array
    {
        foreach ($this->stores($context, $options) as $store) {
            $record = $store->find($id);

            if ($record !== null) {
                return [$store, $record];
            }
        }

        return null;
    }

    /**
     * @param list<array<string, mixed>> $rows
     */
    private function formatTable(array $rows): string
    {
        $widths = [
            'id' => 36,
            'ts_utc' => 20,
            'site' => 24,
            'form' => 14,
            'score' => 5,
            'status' => 9,
            'mail' => 4,
            'phone' => 5,
            'ip' => 17,
        ];

        $header = $this->tableRow([
            'ID' => 'ID',
            'TS_UTC' => 'TS_UTC',
            'SITE' => 'SITE',
            'FORM' => 'FORM',
            'SCORE' => 'SCORE',
            'STATUS' => 'STATUS',
            'MAIL' => 'MAIL',
            'PHONE' => 'PHONE',
            'IP' => 'IP',
            'FIRST REASON' => 'FIRST REASON',
        ], $widths);

        $lines = [$header, str_repeat('-', max(40, mb_strlen($header)))];

        foreach ($rows as $row) {
            $lines[] = $this->tableRow([
                'ID' => self::text($row['id'] ?? null),
                'TS_UTC' => self::text($row['ts_utc'] ?? null),
                'SITE' => self::text($row['site'] ?? null),
                'FORM' => self::text($row['form'] ?? null),
                'SCORE' => self::text($row['score'] ?? null),
                'STATUS' => self::text($row['status'] ?? null),
                'MAIL' => ($row['has_email'] ?? false) === true ? 'yes' : 'no',
                'PHONE' => ($row['has_phone'] ?? false) === true ? 'yes' : 'no',
                'IP' => self::text($row['client_ip'] ?? null),
                'FIRST REASON' => mb_strcut(self::text($row['first_reason'] ?? null), 0, 90),
            ], $widths);
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    /**
     * @param array<string, string> $cells  map header => value
     * @param array<string, int>    $widths
     */
    private function tableRow(array $cells, array $widths): string
    {
        $parts = [];

        foreach ($cells as $header => $value) {
            $width = $header === 'FIRST REASON' ? 0 : ($widths[$this->columnKey($header)] ?? 0);

            $parts[] = $width > 0 ? mb_str_pad($value, $width) : $value;
        }

        return rtrim(implode('  ', $parts));
    }

    private function columnKey(string $header): string
    {
        return match ($header) {
            'ID' => 'id',
            'TS_UTC' => 'ts_utc',
            'SITE' => 'site',
            'FORM' => 'form',
            'SCORE' => 'score',
            'STATUS' => 'status',
            'MAIL' => 'mail',
            'PHONE' => 'phone',
            'IP' => 'ip',
            default => 'reason',
        };
    }

    /**
     * @param array<string, mixed> $view
     */
    private function formatRecord(array $view, bool $reveal): string
    {
        $client = \is_array($view['client'] ?? null) ? self::stringKeyed($view['client']) : [];
        $request = \is_array($view['request'] ?? null) ? self::stringKeyed($view['request']) : [];
        $payload = \is_array($view['payload'] ?? null) ? self::stringKeyed($view['payload']) : [];
        $verdict = \is_array($view['verdict'] ?? null) ? self::stringKeyed($view['verdict']) : [];
        $personal = \is_array($view['personal_data'] ?? null) ? self::stringKeyed($view['personal_data']) : [];
        $reasons = RejectedStore::reasons($view);
        $fields = \is_array($payload['fields'] ?? null) ? self::stringKeyed($payload['fields']) : [];
        $files = \is_array($payload['files'] ?? null) ? array_values($payload['files']) : [];

        $lines = [
            'ID:            ' . self::text($view['id'] ?? null),
            'Created:       ' . self::text($view['ts'] ?? null) . '  (' . self::text($view['ts_utc'] ?? null) . ' UTC)',
            'Status:        ' . self::text($view['display_status'] ?? $view['status'] ?? null)
                . '  (would_reject: ' . (($view['would_reject'] ?? true) === true ? 'yes' : 'no') . ')',
            'Site/Form:     ' . self::text($view['site'] ?? null) . ' / ' . self::text($view['form'] ?? null),
            'Source/Reason: ' . self::text($view['source'] ?? null) . ' / ' . self::text($view['reason'] ?? null),
            'Verdict:       ' . self::text($verdict['status'] ?? null) . ' score ' . self::text($verdict['score'] ?? null),
            'Why blocked:   ' . ($reasons === [] ? '-' : implode('; ', $reasons)),
            'E-mail/phone:  ' . (($personal['has_email'] ?? false) === true ? 'email present' : 'no email')
                . ', ' . (($personal['has_phone'] ?? false) === true ? 'phone present' : 'no phone'),
            'Request:       ' . self::text($request['method'] ?? null) . ' ' . self::text($request['url'] ?? null),
            'Client:        ip=' . self::text($client['ip'] ?? null)
                . ' ua=' . self::text($client['user_agent'] ?? null),
            'Referer:       ' . self::text($client['referer'] ?? null),
            '',
            'Fields (' . \count($fields) . '):',
        ];

        foreach ($fields as $name => $value) {
            $lines[] = '  ' . $name . ' = ' . $this->formatValue($value);
        }

        $lines[] = '';
        $lines[] = 'Body:          ' . self::text($payload['body'] ?? null)
            . ' (' . self::text($payload['body_bytes'] ?? null) . ' bytes)';

        if ($files !== []) {
            $lines[] = 'Files (' . \count($files) . '):';

            foreach ($files as $file) {
                if (!\is_array($file)) {
                    continue;
                }

                $entry = self::stringKeyed($file);
                $lines[] = '  ' . self::text($entry['name'] ?? null)
                    . ' (' . self::text($entry['size'] ?? null) . ' bytes, '
                    . self::text($entry['type'] ?? null)
                    . ', sha256=' . mb_strcut(self::text($entry['sha256'] ?? null), 0, 16) . ')';
            }
        }

        $lines[] = '';
        $lines[] = 'Replay:        php bin/rejected-forms replay ' . self::text($view['id'] ?? null) . ' --dry-run';
        $lines[] = $reveal
            ? 'Personal data: shown in full (--reveal).'
            : 'Personal data: masked. Pass --reveal to print the stored values.';

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    private function formatValue(mixed $value): string
    {
        if (\is_array($value)) {
            return '[array ' . \count($value) . ' items]';
        }

        if (\is_scalar($value) && !\is_bool($value)) {
            return (string) $value;
        }

        if ($value === true) {
            return 'yes';
        }

        if ($value === false) {
            return 'no';
        }

        return '[null]';
    }

    /**
     * @param array<string, mixed> $preview
     * @param list<string>         $reasons
     */
    private function formatPreview(array $preview, array $reasons): string
    {
        $headers = \is_array($preview['headers'] ?? null) ? $preview['headers'] : [];
        $lines = [
            'Dry run: nothing was sent. Add --confirm to send this request.',
            'Original rejection: ' . ($reasons === [] ? '-' : implode('; ', $reasons)),
            '',
            'Method:       ' . self::text($preview['method'] ?? null),
            'URL:          ' . self::text($preview['url'] ?? null),
            'Content type: ' . self::text($preview['content_type'] ?? null),
            'Body:         ' . self::text($preview['body_bytes'] ?? null) . ' bytes',
            'Body preview: ' . self::text($preview['body_preview'] ?? null),
            'Headers:',
        ];

        foreach ($headers as $name => $value) {
            $lines[] = '  ' . $name . ': ' . self::text($value);
        }

        $warnings = \is_array($preview['warnings'] ?? null) ? $preview['warnings'] : [];

        foreach ($warnings as $warning) {
            if (\is_string($warning)) {
                $lines[] = 'Warning: ' . $warning;
            }
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    /**
     * Narrow a value of unknown type to a printable string.
     */
    private static function text(mixed $value, string $default = ''): string
    {
        if (\is_string($value)) {
            return $value;
        }

        if (\is_int($value) || \is_float($value)) {
            return (string) $value;
        }

        return $default;
    }

    /**
     * @param  array<mixed>         $values
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $values): array
    {
        $typed = [];

        foreach ($values as $key => $value) {
            if (\is_string($key)) {
                $typed[$key] = $value;
            }
        }

        return $typed;
    }

    /**
     * @param  list<string>                                                            $args
     * @return array{command: string, id: string, options: array<string, string|bool>}
     */
    private function parse(array $args): array
    {
        $options = [];
        $positional = [];

        foreach ($args as $arg) {
            if ($arg === '--help' || $arg === '-h') {
                $options['help'] = true;
                continue;
            }

            if (str_starts_with($arg, '--')) {
                $equals = strpos($arg, '=');

                if ($equals === false) {
                    $name = substr($arg, 2);

                    if (!\in_array($name, self::FLAGS, true)) {
                        throw new InvalidArgumentException(\sprintf('Option "--%s" requires a value (--name=value).', $name));
                    }

                    $options[$name] = true;
                    continue;
                }

                $name = substr($arg, 2, $equals - 2);

                if (!\in_array($name, self::VALUE_OPTIONS, true)) {
                    throw new InvalidArgumentException(\sprintf('Unknown option "--%s".', $name));
                }

                $options[$name] = substr($arg, $equals + 1);
                continue;
            }

            $positional[] = $arg;
        }

        if (\count($positional) > 2) {
            throw new InvalidArgumentException('Too many arguments.');
        }

        $command = strtolower($positional[0] ?? 'list');

        if (!\in_array($command, ['list', 'show', 'replay', 'ignore', 'purge'], true)) {
            throw new InvalidArgumentException(\sprintf('Unknown command "%s"; expected list, show, replay, ignore or purge.', $command));
        }

        return ['command' => $command, 'id' => $positional[1] ?? '', 'options' => $options];
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function optionString(array $options, string $name): string
    {
        $value = $options[$name] ?? '';

        return \is_string($value) ? $value : '';
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function parseLimit(array $options, int $default): int
    {
        $raw = $this->optionString($options, 'limit');

        if ($raw === '') {
            return $default;
        }

        if (!ctype_digit($raw) || (int) $raw < 1) {
            throw new InvalidArgumentException('--limit expects a positive integer.');
        }

        return (int) $raw;
    }

    private function parseSince(string $raw): int
    {
        if (ctype_digit($raw)) {
            return (int) $raw;
        }

        $timestamp = strtotime($raw);

        if ($timestamp === false) {
            throw new InvalidArgumentException('--since expects YYYY-MM-DD or an epoch timestamp.');
        }

        return $timestamp;
    }

    private function parseDays(string $raw): int
    {
        if (!ctype_digit($raw)) {
            throw new InvalidArgumentException('--older-than expects a non-negative number of days.');
        }

        return (int) $raw;
    }

    private function refuse(string $message): int
    {
        ($this->err)('rejected-forms: ' . $message . PHP_EOL);

        return self::EXIT_REFUSED;
    }

    private function emit(string $text): void
    {
        ($this->out)($text);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function emitJson(array $payload): void
    {
        $encoded = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        ($this->out)($encoded . PHP_EOL);
    }

    private static function slug(string $site): string
    {
        $site = strtolower(trim($site));
        $site = preg_replace('#^www\.#', '', $site) ?? $site;
        $slug = preg_replace('/[^a-z0-9._-]+/', '_', $site);

        return $slug !== null && $slug !== '' ? $slug : 'default';
    }

    public static function usage(): string
    {
        return <<<'TXT'
Usage: php bin/rejected-forms <command> [options] [id]

Commands:
  list                     newest first; --site= --form= --status= --since= --limit= --json
  show <id>                one record; --reveal prints personal data, --json for machines
  replay <id>              rebuild the original request; dry run by default, --confirm to send
                           --url=URL override (same host only, or --allow-host-change)
  ignore <id> --reason=TEXT  mark the record as deliberately not replayed
  purge                    delete old records; --older-than=DAYS, --confirm to delete

Every command: --config=PATH (or SPAM_CHECKER_CONFIG), --path=REGISTRY_ROOT, --site=SITE.
Personal data is masked unless --reveal is given. Exit codes:
  0 success; 1 record/operation refused; 2 usage error; 3 storage or transport error.

TXT;
    }
}
