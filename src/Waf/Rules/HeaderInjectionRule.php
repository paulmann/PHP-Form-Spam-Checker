<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Header injection and request-smuggling shapes.
 *
 * Three signals:
 *  - CR, LF or NUL inside a header value: the classic response-splitting and
 *    log-injection payload;
 *  - an invalid header name;
 *  - a comma inside a header that must carry exactly one value (Host,
 *    Content-Length, Transfer-Encoding), the shape of a smuggling/poisoning
 *    attempt.
 *
 * Header repetition itself cannot be detected from PHP: the SAPI folds
 * repeated header lines into one comma-separated `$_SERVER` value before user
 * code runs. The folded value is exactly what the last check inspects. Headers
 * that legitimately carry lists (X-Forwarded-For, Accept-Language, ...) are
 * excluded from the duplicate check by default.
 */
final class HeaderInjectionRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 80;

    protected const bool DEFAULT_HARD = true;

    /** @var list<string> headers that must never contain a comma-separated list */
    private const array SINGLE_VALUED = ['host', 'content-length', 'transfer-encoding'];

    public function name(): string
    {
        return 'header_injection';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        foreach ($request->headers as $name => $value) {
            $name = (string) $name;

            if ($this->isAllowlisted($name . ': ' . $value)) {
                continue;
            }

            if ($name === '' || preg_match('/^[!#$%&\'*+\-.^_`|~0-9a-zA-Z]+$/', $name) !== 1) {
                return $this->finding(
                    'invalid HTTP header name',
                    'header',
                    ['name' => mb_substr($name, 0, 120)],
                );
            }

            if (preg_match('/[\r\n\0]/', $value) === 1) {
                return $this->finding(
                    'control character in HTTP header value',
                    'header.' . strtolower($name),
                    ['name' => strtolower($name), 'value' => self::preview($value)],
                );
            }
        }

        $singleValued = $this->listOption('single_valued_headers', self::SINGLE_VALUED);

        foreach ($singleValued as $headerName) {
            $value = $request->header($headerName);

            if ($value === '' || !str_contains($value, ',')) {
                continue;
            }

            return $this->finding(
                'duplicated single-valued HTTP header',
                'header.' . strtolower($headerName),
                ['name' => strtolower($headerName), 'value' => self::preview($value)],
            );
        }

        return null;
    }

    private static function preview(string $value): string
    {
        $visible = str_replace(["\r", "\n", "\0"], ['\r', '\n', '\0'], $value);

        return mb_substr($visible, 0, 120);
    }
}
