<?php

declare(strict_types=1);

namespace FormSpamChecker\Cli;

use FormSpamChecker\Config;
use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Waf\Waf;
use FormSpamChecker\Waf\WafRequest;

/**
 * CLI bridge for the WAF (used by non-PHP back ends, e.g. a Node server that
 * wants every API request inspected before the application sees it).
 *
 * Input JSON: {"method":"POST","uri":"/api/lead","ip":"...","headers":{},
 * "cookies":{},"query":{},"body":"...","fields":{},"form":"lead"}
 *
 * Output JSON: {"blocked":bool,"status":"clean|suspicious|blocked","score":int,
 * "findings":[...],"reasons":[...]}
 *
 * Exit codes: 0 allow, 2 block, 3 error.
 */
final class WafCommand
{
    public const int EXIT_ALLOW = 0;
    public const int EXIT_BLOCK = 2;
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

                return self::EXIT_ALLOW;
            }

            $configPath = (string) ($options['config'] ?? getenv('SPAM_CHECKER_CONFIG') ?: '');
            $baseConfig = $configPath !== '' ? Config::fromFile($configPath) : new Config();

            $payload = $this->decode($this->readPayload($options));
            $formId = isset($payload['form']) && is_string($payload['form']) ? $payload['form'] : 'default';
            $config = $baseConfig->form($formId);

            $request = $this->requestFromPayload($payload, $config);

            if (!$config->bool('waf.enabled', false)) {
                $this->emit([
                    'blocked' => false,
                    'status' => 'disabled',
                    'score' => 0,
                    'findings' => [],
                    'reasons' => ['waf disabled in configuration'],
                ]);

                return self::EXIT_ALLOW;
            }

            $waf = Waf::withDefaultRules(
                $config,
                null,
                SpamChecker::createStorage($config),
                new ErrorLogLogger('waf-cli'),
            );

            $verdict = $waf->inspect($request);
            $this->emit([
                'blocked' => $verdict->isBlocked(),
                'status' => $verdict->status,
                'score' => $verdict->score,
                'findings' => array_map(
                    static fn ($finding): array => $finding->toArray(),
                    $verdict->findings,
                ),
                'reasons' => $verdict->reasons(),
            ]);

            return $verdict->isBlocked() ? self::EXIT_BLOCK : self::EXIT_ALLOW;
        } catch (\Throwable $exception) {
            $this->emit([
                'blocked' => false,
                'status' => 'error',
                'score' => 0,
                'findings' => [],
                'reasons' => [$exception->getMessage()],
            ]);
            fwrite(STDERR, 'waf-check: ' . $exception->getMessage() . PHP_EOL);

            return self::EXIT_ERROR;
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function requestFromPayload(array $payload, Config $config): WafRequest
    {
        $headers = [];
        if (isset($payload['headers']) && is_array($payload['headers'])) {
            foreach ($payload['headers'] as $name => $value) {
                if (is_string($name) && is_string($value)) {
                    $headers[strtolower($name)] = $value;
                }
            }
        }

        $cookies = [];
        if (isset($payload['cookies']) && is_array($payload['cookies'])) {
            foreach ($payload['cookies'] as $name => $value) {
                if (is_string($name) && is_string($value)) {
                    $cookies[$name] = $value;
                }
            }
        }

        $query = isset($payload['query']) && is_array($payload['query']) ? $payload['query'] : [];
        $fields = isset($payload['fields']) && is_array($payload['fields']) ? $payload['fields'] : [];
        $body = (string) ($payload['body'] ?? '');
        $contentType = $headers['content-type'] ?? '';
        $contentLength = isset($headers['content-length']) && is_numeric($headers['content-length'])
            ? (int) $headers['content-length']
            : strlen($body);

        $now = $payload['now'] ?? null;

        return new WafRequest(
            method: strtoupper((string) ($payload['method'] ?? 'GET')),
            uri: (string) ($payload['uri'] ?? '/'),
            ip: (string) ($payload['ip'] ?? ''),
            body: $body,
            contentType: $contentType,
            contentLength: $contentLength,
            headers: $headers,
            cookies: $cookies,
            query: $query,
            fields: $fields,
            now: is_int($now) ? $now : null,
            formId: (string) ($payload['form'] ?? 'default'),
        );
    }

    /**
     * @param list<string> $args
     * @return array<string, string|bool>
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

            if ($arg === '--stdin') {
                $options['stdin'] = true;
                continue;
            }

            if (str_starts_with($arg, '--')) {
                $equals = strpos($arg, '=');
                if ($equals === false) {
                    throw new \InvalidArgumentException(sprintf('Option "%s" requires a value (--name=value).', $arg));
                }

                $name = substr($arg, 2, $equals - 2);
                $value = substr($arg, $equals + 1);

                if (!in_array($name, ['config', 'json', 'base64'], true)) {
                    throw new \InvalidArgumentException(sprintf('Unknown option "--%s".', $name));
                }

                $options[$name] = $value;
                continue;
            }

            $positional[] = $arg;
        }

        if ($positional !== []) {
            if (count($positional) > 1) {
                throw new \InvalidArgumentException('Only one positional payload is allowed.');
            }
            $options['positional'] = $positional[0];
        }

        return $options;
    }

    /**
     * @param array<string, string|bool> $options
     */
    private function readPayload(array $options): string
    {
        foreach (['json', 'base64', 'positional'] as $source) {
            if (isset($options[$source]) && is_string($options[$source])) {
                if ($source === 'json') {
                    return $options[$source];
                }

                $decoded = base64_decode($options[$source], true);
                if ($decoded === false) {
                    throw new \InvalidArgumentException(sprintf('Payload in "--%s" is not valid base64.', $source));
                }

                return $decoded;
            }
        }

        if (($options['stdin'] ?? false) === true || stream_isatty(STDIN) === false) {
            $stdin = stream_get_contents(STDIN);
            if ($stdin !== false && trim($stdin) !== '') {
                return $stdin;
            }
        }

        throw new \InvalidArgumentException('No payload: pass --json=, --base64=, a base64 argument or data on STDIN.');
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $raw): array
    {
        try {
            $data = json_decode(trim($raw), true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new \InvalidArgumentException('Payload is not valid JSON: ' . $exception->getMessage());
        }

        if (!is_array($data)) {
            throw new \InvalidArgumentException('Payload must be a JSON object.');
        }

        return $data;
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
Usage: php bin/waf-check [options] [BASE64_PAYLOAD]

  --config=PATH    configuration file (PHP array, JSON or shared-guard site config)
  --json=JSON      inline JSON payload
  --base64=DATA    base64-encoded JSON payload
  --stdin          read the payload from STDIN
  --help           show this help

Payload: {"method":"POST","uri":"/api/lead","ip":"...","headers":{},
          "cookies":{},"query":{},"body":"...","fields":{},"form":"lead"}
Exit codes: 0 allow, 2 block, 3 error.

TXT;
    }
}
