<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;

/**
 * Field length and control characters.
 *
 * Contact forms are short by nature; payloads of tens of kilobytes are either
 * an attack (buffer/DoS, log flooding) or spam. NUL and other control bytes are
 * never legitimate in a text field and are a hard Spam verdict.
 */
final class LengthCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'length';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('length.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $max = max(1, $this->config->int('length.max', 5000));
        $hardMax = max($max, $this->config->int('length.hard_max', 20000));

        $score = 0;
        $evidence = [];

        foreach ($submission->content($this->config->excludedFields()) as $field => $value) {
            if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value) === 1) {
                return CheckResult::spam(
                    $this->name(),
                    sprintf('control characters in field "%s"', $field),
                    ['field' => $field],
                    $this->config->int('length.hard_score', 100),
                );
            }

            $length = mb_strlen($value);

            if ($length > $hardMax) {
                return CheckResult::spam(
                    $this->name(),
                    sprintf('field "%s" is %d characters long (hard max %d)', $field, $length, $hardMax),
                    ['field' => $field, 'length' => $length, 'hard_max' => $hardMax],
                    $this->config->int('length.hard_score', 100),
                );
            }

            if ($length > $max) {
                $score += $this->config->int('length.score', 30);
                $evidence[] = ['field' => $field, 'length' => $length];
            }
        }

        if ($score === 0) {
            return CheckResult::clean($this->name());
        }

        return CheckResult::suspicious(
            $this->name(),
            min(100, $score),
            sprintf('field(s) longer than %d characters', $max),
            ['fields' => $evidence],
        );
    }
}
