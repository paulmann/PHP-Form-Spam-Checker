<?php

declare(strict_types=1);

namespace FormSpamChecker\Security;

use FormSpamChecker\Log\ErrorLogLogger;
use FormSpamChecker\Log\LoggerInterface;

/**
 * Fail2Ban bridge: appends one machine-readable line per abusive request to a
 * log file that a Fail2Ban filter/jail watches.
 *
 * Format (stable, one line per event):
 *
 *     PHPFSC BAN ip=203.0.113.5 site=batterywizard.ru form=lead score=100 reason=spam
 *
 * The matching filter is:
 *
 *     failregex = ^PHPFSC BAN ip=<HOST> .*$
 *
 * Writing is best-effort and fail-open: a broken log path must never break the
 * form. Lines are appended with LOCK_EX so concurrent PHP-FPM workers cannot
 * interleave bytes inside a line.
 */
final class Fail2Ban
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly string $logPath,
        private readonly string $site = '',
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new ErrorLogLogger('fail2ban');
    }

    public function logPath(): string
    {
        return $this->logPath;
    }

    /**
     * Report one IP. Returns false when the line could not be written.
     */
    public function report(string $ip, string $reason, int $score = 0, string $form = ''): bool
    {
        if ($this->logPath === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $directory = \dirname($this->logPath);

        if (!is_dir($directory) && !@mkdir($directory, 0o775, true) && !is_dir($directory)) {
            $this->logger->error('fail2ban: cannot create log directory {dir}', ['dir' => $directory]);

            return false;
        }

        $line = \sprintf(
            "PHPFSC BAN ip=%s site=%s form=%s score=%d reason=%s\n",
            $ip,
            $this->token($this->site),
            $this->token($form),
            max(0, min(100, $score)),
            $this->token($reason),
        );

        $handle = @fopen($this->logPath, 'ab');

        if ($handle === false) {
            $this->logger->error('fail2ban: cannot open {path}', ['path' => $this->logPath]);

            return false;
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return false;
            }

            $written = fwrite($handle, $line);
            flock($handle, LOCK_UN);

            return $written !== false && $written > 0;
        } finally {
            fclose($handle);
        }
    }

    /**
     * One whitespace-free token for a log field (Fail2Ban regexes stay simple).
     */
    private function token(string $value): string
    {
        $safe = preg_replace('/[^A-Za-z0-9_.:;\-]+/', '_', $value);

        return mb_substr($safe === null ? '' : $safe, 0, 120);
    }
}
