<?php

declare(strict_types=1);

namespace FormSpamChecker\Http;

use FormSpamChecker\Config;
use FormSpamChecker\Context;
use FormSpamChecker\SpamChecker;

/**
 * JSON HTTP endpoint for applications whose back end is not PHP.
 *
 * Deployment: point the web server at this class through a thin entry script
 * (see public/check.php), then POST {"form":..., "fields":{...},
 * "context":{...}}. The endpoint never echoes submitted user data back: the
 * response contains the verdict and the evidence produced by the checks.
 *
 * When `endpoint.key` is configured, every request must carry a matching
 * `X-Spam-Checker-Key` header (constant-time comparison).
 */
final class CheckEndpoint
{
    public function __construct(private readonly Config $config)
    {
    }

    public static function fromEnvironment(): self
    {
        $path = getenv('SPAM_CHECKER_CONFIG');

        if (!is_string($path) || $path === '') {
            $default = dirname(__DIR__, 2) . '/config/spam-checker.php';
            $path = is_file($default) ? $default : '';
        }

        return new self($path !== '' ? Config::fromFile($path) : new Config());
    }

    /**
     * Handle the current HTTP request and terminate the script.
     */
    public function handle(): never
    {
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');

        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            http_response_code(405);
            echo $this->json(['status' => 'error', 'error' => 'method not allowed, use POST']);
            exit;
        }

        $key = $this->config->string('endpoint.key');

        if ($key !== '') {
            $provided = (string) ($_SERVER['HTTP_X_SPAM_CHECKER_KEY'] ?? '');

            if (!$this->isAuthorized($provided)) {
                http_response_code(403);
                echo $this->json(['status' => 'error', 'error' => 'forbidden']);
                exit;
            }
        }

        $max = max(1024, $this->config->int('endpoint.max_body_bytes', 262144));
        $raw = file_get_contents('php://input', false, null, 0, $max + 1);

        if ($raw === false) {
            http_response_code(400);
            echo $this->json(['status' => 'error', 'error' => 'cannot read request body']);
            exit;
        }

        if (strlen($raw) > $max) {
            http_response_code(413);
            echo $this->json(['status' => 'error', 'error' => 'request body too large']);
            exit;
        }

        try {
            $payload = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);

            if (!is_array($payload)) {
                throw new \InvalidArgumentException('body must be a JSON object');
            }

            $response = $this->process($payload);
            $statusCode = match ($response['status'] ?? 'error') {
                'spam' => 200,
                'suspicious' => 200,
                'clean' => 200,
                default => 500,
            };
        } catch (\JsonException $exception) {
            $statusCode = 400;
            $response = ['status' => 'error', 'error' => 'invalid JSON: ' . $exception->getMessage()];
        } catch (\Throwable $exception) {
            $statusCode = 500;
            $response = ['status' => 'error', 'error' => 'spam checker error: ' . $exception->getMessage()];
        }

        http_response_code($statusCode);
        echo $this->json($response);
        exit;
    }

    /**
     * Check a decoded payload. Kept public and free of I/O for testability.
     *
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function process(array $payload): array
    {
        $formId = isset($payload['form']) && is_string($payload['form']) && $payload['form'] !== ''
            ? $payload['form']
            : 'default';

        $fields = $payload['fields'] ?? null;

        if (!is_array($fields)) {
            $fields = [];
            foreach ($payload as $key => $value) {
                if (in_array($key, ['form', 'context'], true)) {
                    continue;
                }
                $fields[$key] = $value;
            }
        }

        if (count($fields) > 200) {
            throw new \InvalidArgumentException('too many fields (max 200)');
        }

        $context = isset($payload['context']) && is_array($payload['context'])
            ? Context::fromArray($payload['context'])
            : new Context();

        $verdict = (new SpamChecker($this->config))->check($fields, $context, $formId);

        return ['form' => $formId] + $verdict->toArray();
    }

    public function isAuthorized(string $providedKey): bool
    {
        $key = $this->config->string('endpoint.key');

        if ($key === '') {
            return true;
        }

        return $providedKey !== '' && hash_equals($key, $providedKey);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function json(array $data): string
    {
        return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
