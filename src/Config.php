<?php

declare(strict_types=1);

namespace FormSpamChecker;

use FormSpamChecker\Exception\InvalidConfigException;
use JsonException;

/**
 * Immutable configuration tree with dot-notation access and per-form overrides.
 *
 * Example:
 *
 *     $config = Config::fromArray([
 *         'thresholds' => ['spam' => 55],
 *         'forms' => [
 *             'register' => ['rate_limit' => ['max' => 3, 'window' => 900]],
 *         ],
 *     ]);
 *     $register = $config->form('register');   // still has all global defaults
 *
 * Unknown keys are preserved: the library ignores what it does not understand,
 * which keeps configuration forward-compatible across upgrades.
 */
final class Config
{
    /** @var array<string, mixed> */
    private array $values;

    /**
     * @param array<string, mixed> $values
     */
    public function __construct(array $values = [])
    {
        $this->values = self::deepMerge(self::defaults(), $values);
    }

    /**
     * @param array<string, mixed> $values
     */
    public static function fromArray(array $values): self
    {
        return new self($values);
    }

    /**
     * Load configuration from a PHP file that returns an array or from JSON.
     */
    public static function fromFile(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidConfigException(\sprintf('Configuration file is not readable: %s', $path));
        }

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        if ($extension === 'php') {
            /** @psalm-suppress UnresolvableInclude */
            $data = require $path;
        } else {
            $raw = file_get_contents($path);
            if ($raw === false) {
                throw new InvalidConfigException(\sprintf('Cannot read configuration file: %s', $path));
            }

            try {
                $data = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
            } catch (JsonException $exception) {
                throw new InvalidConfigException(
                    \sprintf('Configuration file is not valid JSON: %s (%s)', $path, $exception->getMessage()),
                    0,
                    $exception,
                );
            }
        }

        if (!\is_array($data)) {
            throw new InvalidConfigException(\sprintf('Configuration file must return an array: %s', $path));
        }

        // A shared-guard site configuration wraps the pipeline configuration in
        // a 'config' key and adds metadata (site, mode, match, skip). Every entry
        // point must understand the same file, so unwrap it here: the CLI bridge
        // and the HTTP endpoint receive exactly the path the guard uses.
        if (
            isset($data['config'])
            && \is_array($data['config'])
            && (isset($data['mode']) || isset($data['site']) || isset($data['match']) || isset($data['skip']))
        ) {
            $data = $data['config'];
        }

        return new self(self::stringKeyed($data));
    }

    public function get(string $path, mixed $default = null): mixed
    {
        $node = $this->values;

        foreach (explode('.', $path) as $segment) {
            if (!\is_array($node) || !\array_key_exists($segment, $node)) {
                return $default;
            }
            $node = $node[$segment];
        }

        return $node;
    }

    public function bool(string $path, bool $default = false): bool
    {
        $value = $this->get($path, $default);

        if (\is_bool($value)) {
            return $value;
        }

        if (\is_int($value) || \is_string($value)) {
            return filter_var($value, FILTER_VALIDATE_BOOL) === true;
        }

        return $default;
    }

    public function int(string $path, int $default = 0): int
    {
        $value = $this->get($path, $default);

        if (\is_int($value)) {
            return $value;
        }

        if (\is_float($value)) {
            return (int) $value;
        }

        if (\is_string($value) && is_numeric($value)) {
            return (int) $value;
        }

        return $default;
    }

    public function float(string $path, float $default = 0.0): float
    {
        $value = $this->get($path, $default);

        if (\is_float($value) || \is_int($value)) {
            return (float) $value;
        }

        if (\is_string($value) && is_numeric($value)) {
            return (float) $value;
        }

        return $default;
    }

    public function string(string $path, string $default = ''): string
    {
        $value = $this->get($path, $default);

        return \is_scalar($value) ? (string) $value : $default;
    }

    /**
     * @param  array<mixed> $default
     * @return array<mixed>
     */
    public function array(string $path, array $default = []): array
    {
        $value = $this->get($path, $default);

        return \is_array($value) ? $value : $default;
    }

    /**
     * Configuration for one form: global values with `forms.<id>` applied on top.
     */
    public function form(string $formId): self
    {
        $override = $this->get('forms.' . $formId, []);

        if (!\is_array($override)) {
            return $this;
        }

        return new self(self::deepMerge($this->values, self::stringKeyed($override)));
    }

    /**
     * Configuration arrays are keyed by string; PHP may hand back integer keys
     * from JSON/list structures, so normalise before merging.
     *
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
     * @param array<string, mixed> $values
     */
    public function with(array $values): self
    {
        return new self(self::deepMerge($this->values, $values));
    }

    /**
     * Shared secret for the signed time-trap token.
     *
     * A missing secret is a configuration error, not a silent no-op: an
     * unsigned token would be trivially forgeable.
     */
    public function secret(): string
    {
        $secret = $this->string('time_trap.secret');

        if (mb_strlen($secret) < 16) {
            throw new InvalidConfigException(
                'time_trap.secret must be set to at least 16 characters when the signed time trap is enabled.',
            );
        }

        return $secret;
    }

    /**
     * Directory used by the file storage when storage.path is not set.
     */
    public function storagePath(): string
    {
        $path = $this->string('storage.path');

        if ($path !== '') {
            return rtrim($path, '/\\');
        }

        return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'php-form-spam-checker';
    }

    /**
     * Directory for cached remote responses (AbuseIPDB, DNS lookups).
     */
    public function cachePath(): string
    {
        $path = $this->string('cache.path');

        return $path !== '' ? rtrim($path, '/\\') : $this->storagePath() . DIRECTORY_SEPARATOR . 'cache';
    }

    /**
     * File Fail2Ban follows for this installation.
     *
     * A blank `fail2ban.log_path` falls back to the state directory, so the
     * shared library works out of the box and site configs usually override it
     * with a per-site file under `var/log/sites/`.
     */
    public function fail2banLogPath(): string
    {
        $path = $this->string('fail2ban.log_path');

        return $path !== '' ? $path : $this->storagePath() . DIRECTORY_SEPARATOR . 'fail2ban.log';
    }

    /**
     * Directory where the Bayesian model is persisted.
     */
    public function bayesStoragePath(): string
    {
        $path = $this->string('bayes.storage_path');

        return $path !== '' ? rtrim($path, '/\\') : $this->storagePath() . DIRECTORY_SEPARATOR . 'bayes';
    }

    /**
     * Field names that must never be inspected as user content.
     *
     * @return list<string>
     */
    public function excludedFields(): array
    {
        $configured = $this->array('fields.exclude', []);

        $default = ['website', '_fs_hp', '_fs_ts', 'consent', 'promo', 'tariff', 'device',
            'devices', 'users', 'term', 'model', 'serial', 'verification', 'verificationUntil'];

        $fields = [];
        foreach ([...$default, ...$configured] as $field) {
            if (\is_string($field) && $field !== '') {
                $fields[] = $field;
            }
        }

        return array_values(array_unique($fields));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->values;
    }

    /**
     * @return array<string, mixed>
     */
    public static function defaults(): array
    {
        return [
            'thresholds' => [
                'suspicious' => 30,
                'spam' => 60,
            ],
            'fields' => [
                'max_length' => 5000,
                'exclude' => [],
            ],
            'honeypot' => [
                'enabled' => true,
                'fields' => ['website', '_fs_hp'],
                'score' => 100,
            ],
            'time_trap' => [
                'enabled' => false,
                'field' => '_fs_ts',
                'secret' => '',
                'min_seconds' => 2,
                'max_seconds' => 604800,
                'require_token' => true,
                'suspicious_score' => 30,
                'spam_score' => 80,
            ],
            'user_agent' => [
                'enabled' => true,
                'allow_empty' => false,
                'extra_blocklist' => [],
                'empty_score' => 40,
                'blocked_score' => 100,
            ],
            'rate_limit' => [
                'enabled' => true,
                'max' => 8,
                'window' => 900,
                'per_form' => true,
                'score' => 100,
            ],
            'keywords' => [
                'enabled' => true,
                'words' => [
                    // Russian
                    'казино', 'казик', 'ставки на спорт', 'букмекер', '1xbet', 'bet365',
                    'заработок', 'заработать в интернете', 'без вложений', 'пассивный доход',
                    'инвестиции', 'инвестор', 'криптовалюта', 'биткоин', 'bitcoin',
                    'быстрый займ', 'микрозайм', 'займ онлайн', 'кредит без',
                    'продвижение сайта', 'раскрутка', 'накрутка', 'ссылочная масса',
                    'пробить по базе', 'обнал', 'финансовая пирамида', 'трейдинг', 'форекс',
                    'forex', 'обход блокировки', 'взлом', 'хакер', 'купить базу',
                    'инфобизнес', 'курсы по заработку', 'удаленная работа от',
                    // English
                    'casino', 'betting', 'viagra', 'cialis', 'porn', 'xxx', 'pharmacy',
                    'payday loan', 'loans', 'crypto', 'backlinks', 'link building',
                    'guest post', 'buy followers', 'replica watches', 'essay writing',
                    'free money', 'get rich', 'seo services', 'seo package',
                ],
                'patterns' => [],
                'per_hit' => 12,
                'max_score' => 90,
                'scan_fields' => [],
            ],
            'links' => [
                'enabled' => true,
                'max' => 2,
                'score_per_extra' => 15,
                'shortener_score' => 35,
                'shorteners' => [
                    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly',
                    'cutt.ly', 'shorturl.at', 'rb.gy', 'clck.ru', 'vk.cc', 'tiny.cc',
                    'rebrand.ly', 'adf.ly', 'shorte.st', 'u.to', 'qps.ru',
                ],
                'obfuscated_score' => 25,
            ],
            'sql_injection' => [
                'enabled' => true,
                'spam_score' => 100,
                'suspicious_score' => 40,
            ],
            'xss' => [
                'enabled' => true,
                'spam_score' => 100,
                'suspicious_score' => 45,
            ],
            'email' => [
                'enabled' => true,
                'fields' => ['email', 'personalEmail', 'e-mail', 'mail'],
                'invalid_score' => 40,
                'disposable_score' => 70,
                'disposable_domains' => [],
            ],
            'length' => [
                'enabled' => true,
                'max' => 5000,
                'score' => 30,
                'hard_max' => 20000,
                'hard_score' => 100,
            ],
            'repetition' => [
                'enabled' => true,
                'min_run' => 12,
                'min_word_repeats' => 4,
                'score' => 25,
                'max_score' => 60,
            ],
            'language' => [
                'enabled' => false,
                'mixed_script_score' => 20,
                'max_score' => 40,
                // Opt-in, disabled by default: require Cyrillic in name-like
                // fields for Russian-language sites.
                'require_cyrillic' => false,
                'missing_score' => 40,
                'min_letters' => 2,
                'fields' => [
                    'name', 'fio', 'fullname', 'full_name', 'firstname', 'first_name',
                    'lastname', 'last_name', 'surname', 'secondname', 'second_name',
                    'middlename', 'middle_name', 'family', 'givenname', 'given_name',
                    'имя', 'фамилия', 'фио',
                ],
            ],
            'log' => [
                'enabled' => false,
                'path' => '',
                'pii' => false,
                'sample_fields' => true,
            ],
            'storage' => [
                'driver' => 'file',
                'path' => '',
            ],
            'endpoint' => [
                'key' => '',
                'max_body_bytes' => 262144,
            ],
            'pipeline' => [
                'stop_on_spam' => true,
            ],
            'http' => [
                'timeout' => 2.0,
                'user_agent' => 'PHP-Form-Spam-Checker/2.0',
            ],
            'cache' => [
                'driver' => 'file',
                'path' => '',
            ],
            'abuseipdb' => [
                'enabled' => false,
                'api_key' => '',
                'threshold' => 90,
                'cache_ttl' => 21600,
                'timeout' => 2.0,
                'max_age_days' => 30,
                'fail_open' => true,
                'circuit_breaker' => [
                    'failures' => 3,
                    'cooldown' => 300,
                ],
            ],
            'dnsbl' => [
                'enabled' => false,
                'zones' => ['zen.spamhaus.org', 'bl.spamcop.net'],
                'cache_ttl' => 3600,
                'timeout' => 2,
                'hit_score' => 100,
            ],
            'spf' => [
                'enabled' => false,
                'fields' => ['email', 'personalEmail'],
                'missing_score' => 10,
                'lookup_limit' => 10,
                'dns_ttl' => 3600,
            ],
            'dmarc' => [
                'enabled' => false,
                'fields' => ['email', 'personalEmail'],
                'missing_score' => 10,
                'weak_policy_score' => 5,
                'dns_ttl' => 3600,
            ],
            'dkim' => [
                'enabled' => false,
                'required' => false,
            ],
            'bayes' => [
                'enabled' => false,
                'storage_path' => '',
                'threshold' => 0.92,
                'min_documents' => 20,
                'score_scale' => 100,
            ],
            'behavioral' => [
                'honeypot' => [
                    'dynamic' => true,
                    'field_prefix' => '_hp_',
                    'secret' => '',
                    'missing_score' => 10,
                ],
                'js_challenge' => [
                    'enabled' => false,
                    'field' => '_js',
                    'missing_score' => 15,
                    'min_ms' => 0,
                ],
            ],
            'waf' => [
                'enabled' => false,
                'mode' => 'monitor',
                'block_status' => 403,
                'max_body_bytes' => 1048576,
                'rules' => [
                    'sql_injection' => true,
                    'xss' => true,
                    'path_traversal' => true,
                    'command_injection' => true,
                    'scanner' => true,
                    'header_injection' => true,
                    'protocol' => true,
                    'ip_reputation' => false,
                    'rate_limit' => false,
                ],
            ],
            'autoban' => [
                'enabled' => false,
                'threshold' => 5,
                'window' => 3600,
                'ttl' => 86400,
            ],
            'fail2ban' => [
                'enabled' => false,
                'log_path' => '',
                'site' => '',
                'emit_on' => 'both',
                'min_score' => 60,
            ],
            'forms' => [],        ];
    }

    /**
     * Recursively merge `$override` into `$base`.
     *
     * Lists (numeric keys) are replaced as a whole: a form that redefines
     * `honeypot.fields` expects exactly its list, not a union with the default.
     *
     * @param  array<string, mixed> $base
     * @param  array<string, mixed> $override
     * @return array<string, mixed>
     */
    private static function deepMerge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (
                \is_array($value)
                && isset($base[$key])
                && \is_array($base[$key])
                && !array_is_list($value)
                && !array_is_list($base[$key])
            ) {
                $base[$key] = self::deepMerge(self::stringKeyed($base[$key]), self::stringKeyed($value));
                continue;
            }

            $base[$key] = $value;
        }

        return $base;
    }
}
