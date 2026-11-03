<?php

declare(strict_types=1);

/**
 * Coverage gate for PHP-Form-Spam-Checker 2.0.
 *
 * Parses a Clover report produced by PHPUnit (php-code-coverage) and fails the
 * build when line or method coverage is below the requested threshold.
 *
 * Usage:
 *   php tools/coverage-gate.php .phpunit.cache/clover.xml
 *   php tools/coverage-gate.php .phpunit.cache/clover.xml --threshold=95 --threshold-methods=90
 *   php tools/coverage-gate.php .phpunit.cache/clover.xml --exclude-env-adapters
 *   php tools/coverage-gate.php .phpunit.cache/clover.xml --format=json
 *
 * Thresholds are split on purpose: line coverage is held to 95 % (the
 * architecture contract targets 100 % for src/ with documented exceptions),
 * while method coverage defaults to 90 % because php-code-coverage counts
 * every declared method, including trivial constructors and one-line getters.
 * A single number for both metrics would either let line coverage rot or force
 * empty tests for getters.
 *
 * Exit codes:
 *   0 - line and method coverage are at or above their thresholds;
 *   1 - at least one metric is below its threshold (gate failure);
 *   2 - usage error, unreadable/invalid Clover file, or no coverage data.
 *
 * Output: a human summary, then exactly one machine-readable line:
 *   COVERAGE_GATE {"schema":"coverage-gate/1",…}
 *
 * --exclude-env-adapters removes the documented environment adapters (thin
 * wrappers around cURL, filesystem, DNS and PSR interfaces) from BOTH the
 * numerator and the denominator: they cannot be unit-tested without the
 * environment and are verified by integration tests instead.
 */

/** Environment adapters documented as excluded from the coverage denominator. */
const ENV_ADAPTER_CLASSES = [
    'Psr18ClientAdapter',
    'Psr16CacheAdapter',
    'Psr6CacheAdapter',
    'Psr3LoggerAdapter',
    'CurlClient',
    'FileCache',
    'DnsGetRecordResolver',
];

const DEFAULT_THRESHOLD_LINES = 95.0;
const DEFAULT_THRESHOLD_METHODS = 90.0;
const EXIT_PASS = 0;
const EXIT_BELOW_THRESHOLD = 1;
const EXIT_USAGE = 2;

/**
 * Print usage information.
 */
function usage(): void
{
    $message = <<<'TXT'
        Usage: php tools/coverage-gate.php <clover.xml> [options]

        Options:
          --threshold=<pct>         Required line coverage (default: 95).
          --threshold-methods=<pct> Required method coverage (default: 90).
          --exclude-env-adapters    Drop the documented environment adapters from the
                                    denominator (CurlClient, FileCache, Psr*Adapter,
                                    DnsGetRecordResolver).
          --exclude-class=<name>    Drop one more class (file basename) from the
                                    denominator. Repeatable.
          --format=human|json       `human` (default) prints the summary and the
                                    machine line; `json` prints only the machine line.
          --help                    Show this help.

        Clover is produced by:
          vendor/bin/phpunit --coverage-clover .phpunit.cache/clover.xml
        and needs a coverage driver (pcov or xdebug) enabled.

        TXT;
    fwrite(STDOUT, $message . PHP_EOL);
}

/**
 * Parse CLI arguments.
 *
 * @param list<string> $arguments argv without the script name
 *
 * @return array{
 *     help: bool,
 *     error: string|null,
 *     clover: string|null,
 *     threshold_lines: float,
 *     threshold_methods: float,
 *     exclude_env_adapters: bool,
 *     format: string,
 *     excluded_classes: list<string>
 * }
 */
function parseArguments(array $arguments): array
{
    $options = [
        'help' => false,
        'error' => null,
        'clover' => null,
        'threshold_lines' => DEFAULT_THRESHOLD_LINES,
        'threshold_methods' => DEFAULT_THRESHOLD_METHODS,
        'exclude_env_adapters' => false,
        'format' => 'human',
        'excluded_classes' => [],
    ];

    $count = count($arguments);
    for ($index = 0; $index < $count; $index++) {
        $argument = $arguments[$index];

        if ($argument === '--help' || $argument === '-h') {
            $options['help'] = true;

            return $options;
        }

        if ($argument === '--exclude-env-adapters') {
            $options['exclude_env_adapters'] = true;

            continue;
        }

        if ($argument === '--threshold' || $argument === '--threshold-methods'
            || $argument === '--format' || $argument === '--exclude-class'
        ) {
            if (!isset($arguments[$index + 1])) {
                $options['error'] = 'Option ' . $argument . ' requires a value.';

                return $options;
            }

            $argument .= '=' . $arguments[$index + 1];
            $index++;
        }

        if (str_starts_with($argument, '--threshold=') || str_starts_with($argument, '--threshold-methods=')) {
            $isMethods = str_starts_with($argument, '--threshold-methods=');
            $prefix = $isMethods ? '--threshold-methods=' : '--threshold=';
            $raw = substr($argument, strlen($prefix));
            if (!is_numeric($raw)) {
                $options['error'] = 'Threshold must be numeric, got "' . $raw . '".';

                return $options;
            }

            $value = (float) $raw;
            if ($value <= 0.0 || $value > 100.0) {
                $options['error'] = 'Threshold must be greater than 0 and at most 100.';

                return $options;
            }

            if ($isMethods) {
                $options['threshold_methods'] = $value;
            } else {
                $options['threshold_lines'] = $value;
            }

            continue;
        }

        if (str_starts_with($argument, '--format=')) {
            $value = substr($argument, strlen('--format='));
            if ($value !== 'human' && $value !== 'json') {
                $options['error'] = 'Format must be "human" or "json", got "' . $value . '".';

                return $options;
            }

            $options['format'] = $value;

            continue;
        }

        if (str_starts_with($argument, '--exclude-class=')) {
            $value = trim(substr($argument, strlen('--exclude-class=')));
            if ($value === '') {
                $options['error'] = 'Class name after --exclude-class must not be empty.';

                return $options;
            }

            $options['excluded_classes'][] = $value;

            continue;
        }

        if (str_starts_with($argument, '-')) {
            $options['error'] = 'Unknown option "' . $argument . '".';

            return $options;
        }

        if ($options['clover'] !== null) {
            $options['error'] = 'Only one Clover path is accepted.';

            return $options;
        }

        $options['clover'] = $argument;
    }

    return $options;
}

/**
 * Metrics of one file in the Clover report.
 *
 * @return array{name: string, class: string, statements: int, covered_statements: int, methods: int, covered_methods: int}|null
 */
function readFileMetrics(object $file): ?array
{
    $name = (string) $file['name'];
    $basename = str_replace('\\', '/', $name);
    $separator = strrpos($basename, '/');
    if ($separator !== false) {
        $basename = substr($basename, $separator + 1);
    }

    $class = str_ends_with($basename, '.php') ? substr($basename, 0, -4) : $basename;

    $statements = 0;
    $coveredStatements = 0;
    $methods = 0;
    $coveredMethods = 0;

    if (count($file->metrics) > 0) {
        $metrics = $file->metrics;
        $statements = (int) $metrics['statements'];
        $coveredStatements = (int) $metrics['coveredstatements'];
        $methods = (int) $metrics['methods'];
        $coveredMethods = (int) $metrics['coveredmethods'];
    } else {
        // Fallback for a Clover dialect without <metrics>: count <line> nodes.
        foreach ($file->line as $line) {
            $type = (string) $line['type'];
            $hits = (int) $line['count'];
            if ($type === 'method') {
                $methods++;
                if ($hits > 0) {
                    $coveredMethods++;
                }
            }

            if ($type === 'method' || $type === 'stmt') {
                $statements++;
                if ($hits > 0) {
                    $coveredStatements++;
                }
            }
        }
    }

    if ($statements === 0 && $methods === 0) {
        return null;
    }

    return [
        'name' => $name,
        'class' => $class,
        'statements' => $statements,
        'covered_statements' => $coveredStatements,
        'methods' => $methods,
        'covered_methods' => $coveredMethods,
    ];
}

/**
 * Read every file entry of a Clover report.
 *
 * @return array{files: list<array{name: string, class: string, statements: int, covered_statements: int, methods: int, covered_methods: int}>, project: array<string, int>|null, duplicate_metrics: list<string>}
 */
function readClover(string $path): array
{
    libxml_use_internal_errors(true);
    $xml = simplexml_load_file($path);
    if ($xml === false) {
        $error = libxml_get_last_error();
        $reason = $error === false ? 'unknown XML error' : trim($error->message);
        throw new RuntimeException('Cannot parse Clover file "' . $path . '": ' . $reason);
    }

    $root = $xml->getName();
    if ($root !== 'coverage' && $root !== 'project' && $root !== 'coverage-project') {
        throw new RuntimeException('Unexpected Clover root element <' . $root . '>, expected <coverage>.');
    }

    $entries = $xml->xpath('//file');
    if ($entries === false) {
        $entries = [];
    }

    $files = [];
    $seen = [];
    foreach ($entries as $entry) {
        $metrics = readFileMetrics($entry);
        if ($metrics === null) {
            continue;
        }

        $key = $metrics['name'];
        if (isset($seen[$key])) {
            continue;
        }

        $seen[$key] = true;
        $files[] = $metrics;
    }

    $project = null;
    $projectMetrics = $xml->xpath('/coverage/project/metrics | /project/metrics');
    if ($projectMetrics !== false && count($projectMetrics) > 0) {
        $metrics = $projectMetrics[0];
        $project = [
            'statements' => (int) $metrics['statements'],
            'covered_statements' => (int) $metrics['coveredstatements'],
            'methods' => (int) $metrics['methods'],
            'covered_methods' => (int) $metrics['coveredmethods'],
        ];
    }

    return ['files' => $files, 'project' => $project];
}

/**
 * Percentage helper, rounded to two decimals.
 */
function percentage(int $covered, int $total): float
{
    if ($total <= 0) {
        return 100.0;
    }

    return round($covered / $total * 100.0, 2);
}

/**
 * Render the gate result and return the process exit code.
 *
 * @param array{
 *     clover: string,
 *     threshold_lines: float,
 *     threshold_methods: float,
 *     format: string,
 *     line_percent: float,
 *     method_percent: float,
 *     covered_lines: int,
 *     total_lines: int,
 *     covered_methods: int,
 *     total_methods: int,
 *     analysed: int,
 *     excluded: list<string>,
 *     exclude_env_adapters: bool,
 *     project_totals: array<string, int>|null,
 *     project_totals_match: bool|null,
 *     failures: list<string>
 * } $result
 */
function report(array $result): int
{
    $passed = $result['failures'] === [];

    if ($result['format'] === 'human') {
        $excluded = $result['excluded'] === []
            ? 'none'
            : implode(', ', $result['excluded']) . ' (' . count($result['excluded']) . ')';

        $lines = [
            '',
            'Coverage gate',
            '  clover  : ' . $result['clover'],
            '  files   : ' . $result['analysed'] . ' analysed, excluded: ' . $excluded,
            '  lines   : ' . $result['covered_lines'] . '/' . $result['total_lines']
                . '  ' . number_format($result['line_percent'], 2) . '%'
                . '  (threshold ' . number_format($result['threshold_lines'], 2) . '%)',
            '  methods : ' . $result['covered_methods'] . '/' . $result['total_methods']
                . '  ' . number_format($result['method_percent'], 2) . '%'
                . '  (threshold ' . number_format($result['threshold_methods'], 2) . '%)',
        ];

        if ($result['project_totals'] !== null && $result['project_totals_match'] === false) {
            $lines[] = '  warning : per-file metrics do not add up to the Clover project total;'
                . ' the gate uses per-file metrics so exclusions stay honest.';
        }

        $lines[] = '  result  : ' . ($passed ? 'PASS' : 'FAIL - ' . implode('; ', $result['failures']));
        $lines[] = '';

        fwrite(STDOUT, implode(PHP_EOL, $lines) . PHP_EOL);
    }

    $machine = [
        'schema' => 'coverage-gate/2',
        'clover' => $result['clover'],
        'threshold_lines' => $result['threshold_lines'],
        'threshold_methods' => $result['threshold_methods'],
        'line_percent' => $result['line_percent'],
        'method_percent' => $result['method_percent'],
        'covered_lines' => $result['covered_lines'],
        'total_lines' => $result['total_lines'],
        'covered_methods' => $result['covered_methods'],
        'total_methods' => $result['total_methods'],
        'files_analysed' => $result['analysed'],
        'files_excluded' => $result['excluded'],
        'exclude_env_adapters' => $result['exclude_env_adapters'],
        'project_totals_match' => $result['project_totals_match'],
        'passed' => $passed,
        'failures' => $result['failures'],
    ];

    $json = json_encode($machine, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    fwrite(STDOUT, 'COVERAGE_GATE ' . ($json === false ? '{}' : $json) . PHP_EOL);

    return $passed ? EXIT_PASS : EXIT_BELOW_THRESHOLD;
}

/**
 * Entry point.
 *
 * @param list<string> $arguments argv without the script name
 */
function main(array $arguments): int
{
    $options = parseArguments($arguments);

    if ($options['help']) {
        usage();

        return EXIT_PASS;
    }

    if ($options['error'] !== null) {
        fwrite(STDERR, 'coverage-gate: ' . $options['error'] . PHP_EOL);
        usage();

        return EXIT_USAGE;
    }

    if ($options['clover'] === null) {
        fwrite(STDERR, 'coverage-gate: missing Clover XML path.' . PHP_EOL);
        usage();

        return EXIT_USAGE;
    }

    $cloverPath = $options['clover'];
    if (!is_file($cloverPath)) {
        fwrite(STDERR, 'coverage-gate: Clover file not found: ' . $cloverPath . PHP_EOL);
        fwrite(STDERR, 'coverage-gate: run PHPUnit with --coverage-clover first.' . PHP_EOL);

        return EXIT_USAGE;
    }

    try {
        $report = readClover($cloverPath);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, 'coverage-gate: ' . $exception->getMessage() . PHP_EOL);

        return EXIT_USAGE;
    }

    $excludedClassNames = $options['excluded_classes'];
    if ($options['exclude_env_adapters']) {
        $excludedClassNames = array_merge($excludedClassNames, ENV_ADAPTER_CLASSES);
    }

    $excludedLookup = [];
    foreach ($excludedClassNames as $className) {
        $excludedLookup[strtolower($className)] = true;
    }

    $totalLines = 0;
    $coveredLines = 0;
    $totalMethods = 0;
    $coveredMethods = 0;
    $analysed = 0;
    $excluded = [];

    foreach ($report['files'] as $file) {
        if ($excludedLookup !== [] && isset($excludedLookup[strtolower($file['class'])])) {
            $excluded[] = $file['class'];

            continue;
        }

        $analysed++;
        $totalLines += $file['statements'];
        $coveredLines += $file['covered_statements'];
        $totalMethods += $file['methods'];
        $coveredMethods += $file['covered_methods'];
    }

    if ($totalLines === 0 && $totalMethods === 0) {
        fwrite(STDERR, 'coverage-gate: no coverage data found in ' . $cloverPath . PHP_EOL);
        fwrite(STDERR, 'coverage-gate: is a coverage driver (pcov/xdebug) enabled and src/ in the source filter?' . PHP_EOL);

        return EXIT_USAGE;
    }

    $linePercent = percentage($coveredLines, $totalLines);
    $methodPercent = percentage($coveredMethods, $totalMethods);
    $thresholdLines = $options['threshold_lines'];
    $thresholdMethods = $options['threshold_methods'];

    $failures = [];
    if ($linePercent < $thresholdLines) {
        $failures[] = 'line coverage ' . number_format($linePercent, 2) . '% < ' . number_format($thresholdLines, 2) . '%';
    }

    if ($totalMethods > 0 && $methodPercent < $thresholdMethods) {
        $failures[] = 'method coverage ' . number_format($methodPercent, 2) . '% < ' . number_format($thresholdMethods, 2) . '%';
    }

    $projectTotalsMatch = null;
    if ($report['project'] !== null) {
        $projectTotalsMatch = $report['project']['statements'] === $totalLines
            && $report['project']['covered_statements'] === $coveredLines
            && $report['project']['methods'] === $totalMethods
            && $report['project']['covered_methods'] === $coveredMethods;
    }

    return report([
        'clover' => $cloverPath,
        'threshold_lines' => $thresholdLines,
        'threshold_methods' => $thresholdMethods,
        'format' => $options['format'],
        'line_percent' => $linePercent,
        'method_percent' => $methodPercent,
        'covered_lines' => $coveredLines,
        'total_lines' => $totalLines,
        'covered_methods' => $coveredMethods,
        'total_methods' => $totalMethods,
        'analysed' => $analysed,
        'excluded' => $excluded,
        'exclude_env_adapters' => $options['exclude_env_adapters'],
        'project_totals' => $report['project'],
        'project_totals_match' => $projectTotalsMatch,
        'failures' => $failures,
    ]);
}

exit(main(array_slice($argv, 1)));
