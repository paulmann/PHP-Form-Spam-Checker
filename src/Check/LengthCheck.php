<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;

/**
 * Field length and control characters: oversized payloads are an attack or spam,
 * NUL/control bytes are never legitimate in a text field.
 */
final readonly class LengthCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'length';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('length.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $max = max(1, $this->config->int('length.max', 5000));
        $hardMax = max($max, $this->config->int('length.hard_max', 20000));
        $score = 0;
        $evidence = [];

        foreach ($data->content($this->config->excludedFields()) as $field => $value) {
            if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value) === 1) {
                return new CheckOutcome(
                    $this->name(),
                    CheckStatus::SPAM,
                    $this->config->int('length.hard_score', 100),
                    sprintf('control characters in field "%s"', $field),
                    ['field' => $field],
                );
            }

            $length = mb_strlen($value);

            if ($length > $hardMax) {
                return new CheckOutcome(
                    $this->name(),
                    CheckStatus::SPAM,
                    $this->config->int('length.hard_score', 100),
                    sprintf('field "%s" is %d characters long (hard max %d)', $field, $length, $hardMax),
                    ['field' => $field, 'length' => $length, 'hard_max' => $hardMax],
                );
            }

            if ($length > $max) {
                $score += $this->config->int('length.score', 30);
                $evidence[] = ['field' => $field, 'length' => $length];
            }
        }

        if ($score === 0) {
            return CheckOutcome::ham($this->name());
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(100, $score),
            sprintf('field(s) longer than %d characters', $max),
            ['fields' => $evidence],
        );
    }
}
