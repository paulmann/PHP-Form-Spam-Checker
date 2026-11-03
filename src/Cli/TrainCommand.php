<?php

declare(strict_types=1);

namespace FormSpamChecker\Cli;

use FormSpamChecker\Config;
use FormSpamChecker\SpamChecker;

/**
 * Trains and inspects the Bayesian model from the command line.
 *
 * Examples:
 *   php bin/spam-train --config=config/spam.php --ham=ham.txt --spam=spam.txt
 *   php bin/spam-train --config=config/spam.php --text-spam="casino bitcoin"
 *   php bin/spam-train --config=config/spam.php --stats
 *   php bin/spam-train --config=config/spam.php --reset
 *
 * Training files contain one document per line (blank lines and lines starting
 * with "#" are skipped). The model is persisted through the configured cache
 * (bayes.storage_path is used as the cache key namespace).
 */
final class TrainCommand
{
    public const int EXIT_OK = 0;
    public const int EXIT_ERROR = 3;

    /**
     * @param list<string> $argv
     */
    public function run(array $argv): int
    {
        try {
            $options = $this->parse(array_slice($argv, 1));

            if (($options['help'] ?? false) === true) {
                fwrite(STDERR, self::usage());

                return self::EXIT_OK;
            }

            $configPath = (string) ($options['config'] ?? getenv('SPAM_CHECKER_CONFIG') ?: '');
            $config = $configPath !== '' ? Config::fromFile($configPath) : new Config();

            $classifier = SpamChecker::createBayesClassifier($config);

            if (($options['reset'] ?? false) === true) {
                $classifier->reset();
                $this->emit(['reset' => true]);
            }

            if (($options['stats'] ?? false) === true) {
                $this->emit(['stats' => $classifier->stats()]);

                return self::EXIT_OK;
            }

            $ham = $this->documents($options, 'ham');
            $spam = $this->documents($options, 'spam');

            if ($ham === [] && $spam === []) {
                throw new \InvalidArgumentException('Nothing to train: pass --ham=, --spam=, --text-ham= or --text-spam=.');
            }

            foreach ($ham as $document) {
                $classifier->train($document, false);
            }

            foreach ($spam as $document) {
                $classifier->train($document, true);
            }

            $classifier->persist();

            $this->emit([
                'trained' => ['ham' => count($ham), 'spam' => count($spam)],
                'stats' => $classifier->stats(),
                'persisted' => true,
            ]);

            return self::EXIT_OK;
        } catch (\Throwable $exception) {
            $this->emit(['error' => $exception->getMessage()]);
            fwrite(STDERR, 'spam-train: ' . $exception->getMessage() . PHP_EOL);

            return self::EXIT_ERROR;
        }
    }

    /**
     * @param array<string, string|bool> $options
     * @return list<string>
     */
    private function documents(array $options, string $class): array
    {
        $documents = [];

        $text = $options['text-' . $class] ?? null;
        if (is_string($text) && $text !== '') {
            $documents[] = $text;
        }

        $files = $options[$class] ?? null;
        if (!is_string($files) || $files === '') {
            return $documents;
        }

        foreach (explode(',', $files) as $path) {
            $path = trim($path);
            if ($path === '') {
                continue;
            }

            if (!is_file($path) || !is_readable($path)) {
                throw new \InvalidArgumentException(sprintf('Training file is not readable: %s', $path));
            }

            $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines === false) {
                throw new \InvalidArgumentException(sprintf('Cannot read training file: %s', $path));
            }

            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#')) {
                    continue;
                }
                $documents[] = $line;
            }
        }

        return $documents;
    }

    /**
     * @param list<string> $args
     * @return array<string, string|bool>
     */
    private function parse(array $args): array
    {
        $options = [];

        foreach ($args as $arg) {
            if ($arg === '--help' || $arg === '-h') {
                $options['help'] = true;
                continue;
            }

            if (in_array($arg, ['--reset', '--stats'], true)) {
                $options[substr($arg, 2)] = true;
                continue;
            }

            if (!str_starts_with($arg, '--')) {
                throw new \InvalidArgumentException(sprintf('Unexpected argument "%s".', $arg));
            }

            $equals = strpos($arg, '=');
            if ($equals === false) {
                throw new \InvalidArgumentException(sprintf('Option "%s" requires a value (--name=value).', $arg));
            }

            $name = substr($arg, 2, $equals - 2);
            $value = substr($arg, $equals + 1);

            if (!in_array($name, ['config', 'ham', 'spam', 'text-ham', 'text-spam'], true)) {
                throw new \InvalidArgumentException(sprintf('Unknown option "--%s".', $name));
            }

            $options[$name] = $value;
        }

        return $options;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function emit(array $payload): void
    {
        fwrite(STDOUT, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL);
    }

    public static function usage(): string
    {
        return <<<'TXT'
Usage: php bin/spam-train [options]

  --config=PATH      configuration file (PHP array, JSON or site config)
  --ham=FILES        comma-separated files, one non-spam document per line
  --spam=FILES       comma-separated files, one spam document per line
  --text-ham=TEXT    train one inline non-spam document
  --text-spam=TEXT   train one inline spam document
  --stats            print model statistics and exit
  --reset            drop the current model before training
  --help             show this help

Exit codes: 0 ok, 3 error.

TXT;
    }
}
