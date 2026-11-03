<?php

declare(strict_types=1);

namespace FormSpamChecker;

use FormSpamChecker\Checks\EmailCheck;
use FormSpamChecker\Checks\HoneypotCheck;
use FormSpamChecker\Checks\KeywordCheck;
use FormSpamChecker\Checks\LanguageCheck;
use FormSpamChecker\Checks\LengthCheck;
use FormSpamChecker\Checks\LinkCheck;
use FormSpamChecker\Checks\RateLimitCheck;
use FormSpamChecker\Checks\RepetitionCheck;
use FormSpamChecker\Checks\SqlInjectionCheck;
use FormSpamChecker\Checks\TimeTrapCheck;
use FormSpamChecker\Checks\UserAgentCheck;
use FormSpamChecker\Checks\XssCheck;
use FormSpamChecker\Log\VerdictLogger;
use FormSpamChecker\Storage\FileStorage;
use FormSpamChecker\Storage\MemoryStorage;
use FormSpamChecker\Storage\StorageInterface;

/**
 * Entry point: builds the check pipeline from configuration and decides
 * whether a submission is clean, suspicious or spam.
 *
 *     $checker = new SpamChecker(Config::fromFile(__DIR__ . '/spam.php'));
 *     $verdict = $checker->check($_POST, Context::fromGlobals(), 'contact');
 *     if ($verdict->isSpam()) { http_response_code(400); exit; }
 *
 * The checker is stateless between calls apart from the injected storage, so it
 * can be created per request (cheap) or reused in long-running workers.
 */
final class SpamChecker
{
    /**
     * @param list<CheckInterface>|null $checks custom checks; null means the standard pipeline
     */
    public function __construct(
        private readonly Config $config,
        private readonly ?StorageInterface $storage = null,
        private readonly ?array $checks = null,
    ) {
    }

    /**
     * @param list<CheckInterface>|null $checks
     */
    public static function fromConfig(Config $config, ?StorageInterface $storage = null, ?array $checks = null): self
    {
        return new self($config, $storage, $checks);
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * Check a submission.
     *
     * @param array<string, mixed> $fields
     */
    public function check(array $fields, ?Context $context = null, string $formId = 'default'): Verdict
    {
        $submission = new Submission(
            $fields,
            $context ?? Context::fromGlobals(),
            $formId,
        );

        return $this->checkSubmission($submission);
    }

    public function checkSubmission(Submission $submission): Verdict
    {
        $config = $this->config->form($submission->formId);
        $storage = $this->storage ?? self::createStorage($config);
        $checks = $this->checks ?? self::defaultChecks($config, $storage);

        $verdict = (new Pipeline($checks))->run($submission, $config);

        $this->log($config, $verdict, $submission);

        return $verdict;
    }

    /**
     * The standard, cost-aware check order: local cheap signals first, then
     * content analysis. No check performs network I/O.
     *
     * @return list<CheckInterface>
     */
    public static function defaultChecks(Config $config, StorageInterface $storage): array
    {
        return [
            new HoneypotCheck($config),
            new TimeTrapCheck($config),
            new UserAgentCheck($config),
            new RateLimitCheck($config, $storage),
            new LengthCheck($config),
            new SqlInjectionCheck($config),
            new XssCheck($config),
            new LinkCheck($config),
            new KeywordCheck($config),
            new EmailCheck($config),
            new RepetitionCheck($config),
            new LanguageCheck($config),
        ];
    }

    public static function createStorage(Config $config): StorageInterface
    {
        return match ($config->string('storage.driver', 'file')) {
            'memory' => new MemoryStorage(),
            default => new FileStorage($config->storagePath()),
        };
    }

    private function log(Config $config, Verdict $verdict, Submission $submission): void
    {
        if (!$config->bool('log.enabled', false)) {
            return;
        }

        $path = $config->string('log.path');

        if ($path === '') {
            return;
        }

        $logger = new VerdictLogger(
            $path,
            $config->bool('log.pii', false),
            $config->bool('log.sample_fields', true),
        );

        try {
            $logger->log($verdict, $submission);
        } catch (\Throwable) {
            // Logging must never break form processing.
        }
    }
}
