<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Integration;

use FormSpamChecker\Config;
use FormSpamChecker\Http\CheckEndpoint;
use FormSpamChecker\Tests\Support\TempDirTestCase;
use InvalidArgumentException;

/**
 * HTTP bridge tests: the in-process handler and a real request against the
 * PHP built-in server (public/check.php).
 */
final class EndpointTest extends TempDirTestCase
{
    private const string UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    public function testProcessCleanPayload(): void
    {
        $endpoint = new CheckEndpoint(new Config(['storage' => ['driver' => 'memory']]));

        $response = $endpoint->process([
            'form' => 'contact',
            'fields' => ['name' => 'Иван', 'email' => 'ivan@example.ru', 'message' => 'Нужен отчёт.'],
            'context' => ['ip' => '203.0.113.1', 'userAgent' => self::UA],
        ]);

        self::assertSame('clean', $response['status']);
        self::assertSame('contact', $response['form']);
    }

    public function testProcessSpamPayload(): void
    {
        $endpoint = new CheckEndpoint(new Config(['storage' => ['driver' => 'memory']]));

        $response = $endpoint->process([
            'form' => 'contact',
            'fields' => ['name' => 'bot', 'website' => 'filled'],
            'context' => ['ip' => '203.0.113.2', 'userAgent' => self::UA],
        ]);

        self::assertSame('spam', $response['status']);
        self::assertNotSame([], $response['reasons']);
    }

    public function testFlatPayloadIsAcceptedAsFields(): void
    {
        $endpoint = new CheckEndpoint(new Config(['storage' => ['driver' => 'memory']]));

        $response = $endpoint->process([
            'name' => 'Иван',
            'email' => 'ivan@example.ru',
            'context' => ['ip' => '203.0.113.7', 'userAgent' => self::UA],
        ]);

        self::assertSame('default', $response['form']);
        self::assertSame('clean', $response['status']);
    }

    public function testTooManyFieldsIsRejected(): void
    {
        $endpoint = new CheckEndpoint(new Config(['storage' => ['driver' => 'memory']]));
        $fields = [];
        for ($i = 0; $i < 201; $i++) {
            $fields['field' . $i] = 'x';
        }

        $this->expectException(InvalidArgumentException::class);
        $endpoint->process(['fields' => $fields]);
    }

    public function testAuthorization(): void
    {
        $endpoint = new CheckEndpoint(new Config(['endpoint' => ['key' => 'secret-key']]));

        self::assertFalse($endpoint->isAuthorized(''));
        self::assertFalse($endpoint->isAuthorized('wrong'));
        self::assertTrue($endpoint->isAuthorized('secret-key'));

        $open = new CheckEndpoint(new Config());
        self::assertTrue($open->isAuthorized(''));
    }

    public function testHttpServerCleanAndRejectedRequests(): void
    {
        $root = \dirname(__DIR__, 2);
        $port = random_int(18000, 18800);
        $log = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'spam-checker-server-' . $port . '.log';
        $configPath = $this->tempDir() . '/endpoint-config.json';
        file_put_contents($configPath, '{"storage":{"driver":"memory"},"cache":{"driver":"memory"}}');

        $env = getenv();
        $env['SPAM_CHECKER_CONFIG'] = $configPath;

        $process = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $root . DIRECTORY_SEPARATOR . 'public'],
            [1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']],
            $pipes,
            $root,
            $env,
        );

        self::assertIsResource($process);

        try {
            self::assertTrue($this->waitForServer($port), 'PHP built-in server did not start');

            $payload = json_encode([
                'form' => 'contact',
                'fields' => ['name' => 'Иван', 'email' => 'ivan@example.ru'],
                'context' => ['ip' => '203.0.113.9', 'userAgent' => self::UA],
            ]);

            [$status, $body] = $this->post('http://127.0.0.1:' . $port . '/check.php', (string) $payload);
            self::assertSame(200, $status);
            self::assertSame('clean', json_decode($body, true)['status'] ?? null);

            [$status, $body] = $this->post(
                'http://127.0.0.1:' . $port . '/check.php',
                (string) json_encode(['fields' => ['name' => 'bot', 'website' => 'x']]),
            );
            self::assertSame(200, $status);
            self::assertSame('spam', json_decode($body, true)['status'] ?? null);

            [$status] = $this->post('http://127.0.0.1:' . $port . '/check.php', '{broken');
            self::assertSame(400, $status);

            [$status] = $this->get('http://127.0.0.1:' . $port . '/check.php');
            self::assertSame(405, $status);
        } finally {
            proc_terminate($process);
            proc_close($process);
        }
    }

    private function waitForServer(int $port): bool
    {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $socket = @fsockopen('127.0.0.1', $port, $errorCode, $errorMessage, 0.2);
            if (\is_resource($socket)) {
                fclose($socket);

                return true;
            }
            usleep(100_000);
        }

        return false;
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function post(string $url, string $body): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $body,
                'ignore_errors' => true,
                'timeout' => 10,
            ],
        ]);

        $response = file_get_contents($url, false, $context);
        $headers = $http_response_header ?? [];
        $status = 0;

        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                $status = (int) $matches[1];
                break;
            }
        }

        return [$status, (string) $response];
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function get(string $url): array
    {
        $context = stream_context_create([
            'http' => ['method' => 'GET', 'ignore_errors' => true, 'timeout' => 10],
        ]);

        $response = file_get_contents($url, false, $context);
        $headers = $http_response_header ?? [];
        $status = 0;

        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                $status = (int) $matches[1];
                break;
            }
        }

        return [$status, (string) $response];
    }
}
