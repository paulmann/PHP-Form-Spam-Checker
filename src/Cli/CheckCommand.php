<?php

declare(strict_types=1);

namespace FormSpamChecker\Cli;

use FormSpamChecker\Config;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\SpamChecker;
use FormSpamChecker\Status;
use InvalidArgumentException;
use JsonException;
use Throwable;

/**
 * CLI bridge for non-PHP back ends.
 *
 * Reads a submission as JSON (inline, base64 argument or STDIN) and prints the
 * verdict as a single JSON object on STDOUT. Nothing else is written to STDOUT,
 * so a caller can `json_decode()` the output unconditionally.
 *
 * Usage:
 *   php bin/spam-check --config=/etc/spam.php --form=register --base64=BASE64
 *   echo '{"fields":{...}}' | php bin/spam-check --form=contact
 *   php bin/spam-check --json='{"fields":{"email":"a@b.c"}}'
 *
 * Exit codes: 0 clean, 1 suspicious, 2 spam, 3 error.
 */
final class CheckCommand
{
    public const int EXIT_CLEAN = 0;
    public const int EXIT_SUSPICIOUS = 1;
    public const int EXIT_SPAM = 2;
    public const int EXIT_ERROR = 3;

    /**
     * @param list<string> $argv raw argv (index 0 is the script name)
     */
    public function run(array $argv): int
    {
        try {
            $options = $this->parse(\array_slice($argv, 1));

            if (($options['help'] ?? false) === true) {
                fwrite(STDERR, self::usage());

                return self::EXIT_CLEAN;
            }

            $configOption = $options['config'] ?? null;
            $configPath = \is_string($configOption) ? $configOption : '';
            if ($configPath === '') {
                $environmentPath = getenv('SPAM_CHECKER_CONFIG');
                $configPath = \is_string($environmentPath) ? $environmentPath : '';
            }
            $config = $configPath !== '' ? Config::fromFile($configPath) : new Config();

            $payload = $this->decode($this->readPayload($options));

            $formId = isset($options['form']) && \is_string($options['form'])
                ? $options['form']
                : (isset($payload['form']) && \is_string($payload['form']) ? $payload['form'] : 'default');

            $request = $this->requestFromPayload($payload, $formId);
            $verdict = (new SpamChecker($config))->checkRequest($request);

            $this->emit(['form' => $formId] + $verdict->toArray());

            return match ($verdict->status) {
                Status::Spam => self::EXIT_SPAM,
                Status::Suspicious => self::EXIT_SUSPICIOUS,
                Status::Clean => self::EXIT_CLEAN,
            };
        } catch (Throwable $exception) {
            $this->emit(['status' => 'error', 'score' => 0, 'reasons' => [$exception->getMessage()]]);
            fwrite(STDERR, 'spam-check: ' . $exception->getMessage() . PHP_EOL);

            return self::EXIT_ERROR;
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function requestFromPayload(array $payload, string $formId): RequestData
    {
        $fields = [];
        $rawFields = $payload['fields'] ?? null;
        if (\is_array($rawFields)) {
            foreach ($rawFields as $name => $value) {
                if (\is_string($name)) {
                    $fields[$name] = $value;
                }
            }
        } else {
            foreach ($payload as $key => $value) {
                if (\in_array($key, ['form', 'context'], true)) {
                    continue;
                }
                $fields[$key] = $value;
            }
        }

        if (\count($fields) > 200) {
            throw new InvalidArgumentException('Too many fields in the payload (max 200).');
        }

        $context = isset($payload['context']) && \is_array($payload['context']) ? $payload['context'] : [];

        $headers = [];
        if (isset($context['headers']) && \is_array($context['headers'])) {
            foreach ($context['headers'] as $name => $value) {
                if (\is_string($name) && \is_string($value)) {
                    $headers[strtolower($name)] = $value;
                }
            }
        }

        $userAgent = $context['userAgent'] ?? $context['user_agent'] ?? $context['ua'] ?? '';
        if (!\is_string($userAgent)) {
            $userAgent = '';
        }
        if ($userAgent !== '') {
            $headers['user-agent'] = $userAgent;
        }

        $referer = $context['referer'] ?? '';
        if (!\is_string($referer)) {
            $referer = '';
        }
        if ($referer !== '') {
            $headers['referer'] = $referer;
        }

        $now = $context['now'] ?? null;
        if (\is_string($now) && ctype_digit($now)) {
            $now = (int) $now;
        }

        $ip = $context['ip'] ?? '';
        if (!\is_string($ip)) {
            $ip = '';
        }

        $method = $context['method'] ?? 'POST';
        if (!\is_string($method) || $method === '') {
            $method = 'POST';
        }

        $uri = $context['page'] ?? $context['uri'] ?? '';
        if (!\is_string($uri)) {
            $uri = '';
        }

        $body = $payload['body'] ?? '';
        if (!\is_string($body)) {
            $body = '';
        }

        return new RequestData(
            fields: $fields,
            ip: $ip,
            headers: $headers,
            method: $method,
            uri: $uri,
            body: $body,
            now: \is_int($now) ? $now : null,
            formId: $formId,
        );
    }

    /**
     * @param  list<string>               $args
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
                    throw new InvalidArgumentException(\sprintf('Option "%s" requires a value (--name=value).', $arg));
                }

                $name = substr($arg, 2, $equals - 2);
                $value = substr($arg, $equals + 1);

                if (!\in_array($name, ['config', 'form', 'json', 'base64'], true)) {
                    throw new InvalidArgumentException(\sprintf('Unknown option "--%s".', $name));
                }

                $options[$name] = $value;
                continue;
            }

            $positional[] = $arg;
        }

        if ($positional !== []) {
            if (\count($positional) > 1) {
                throw new InvalidArgumentException('Only one positional payload is allowed.');
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
            if (isset($options[$source]) && \is_string($options[$source])) {
                if ($source === 'json') {
                    return $options[$source];
                }

                $decoded = base64_decode($options[$source], true);
                if ($decoded === false) {
                    throw new InvalidArgumentException(\sprintf('Payload in "--%s" is not valid base64.', $source));
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

        throw new InvalidArgumentException('No payload: pass --json=, --base64=, a base64 argument or data on STDIN. ' . self::usage());
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            throw new InvalidArgumentException('Empty payload.');
        }

        try {
            $data = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Payload is not valid JSON: ' . $exception->getMessage());
        }

        if (!\is_array($data)) {
            throw new InvalidArgumentException('Payload must be a JSON object.');
        }

        $payload = [];
        foreach ($data as $key => $value) {
            if (\is_string($key)) {
                $payload[$key] = $value;
            }
        }

        return $payload;
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
Usage: php bin/spam-check [options] [BASE64_PAYLOAD]

  --config=PATH    configuration file (PHP array, JSON or shared-guard site config)
  --form=ID        form identifier, default "default"
  --json=JSON      inline JSON payload
  --base64=DATA    base64-encoded JSON payload
  --stdin          read the payload from STDIN
  --help           show this help

Payload: {"form":"register","fields":{...},"context":{"ip":"...","userAgent":"..."}}
Exit codes: 0 clean, 1 suspicious, 2 spam, 3 error.

TXT;
    }
}
