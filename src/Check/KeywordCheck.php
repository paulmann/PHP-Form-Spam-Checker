<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * Spam-keyword scoring over the submitted text.
 *
 * Multibyte and case-insensitive. Never a hard Spam verdict: keywords are a
 * signal and the pipeline threshold decides, so a B2B message that mentions an
 * unfortunate word is not blocked by this check alone.
 */
final readonly class KeywordCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'keywords';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('keywords.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $exclude = $this->config->excludedFields();
        $scanFields = $this->config->array('keywords.scan_fields', []);
        $content = $data->content($exclude);

        if ($scanFields !== []) {
            $allowed = [];
            foreach ($scanFields as $field) {
                if (is_string($field) && isset($content[$field])) {
                    $allowed[$field] = $content[$field];
                }
            }
            $content = $allowed;
        }

        if ($content === []) {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        $text = mb_strtolower(implode("\n", $content));
        $hits = [];
        $perHit = max(1, $this->config->int('keywords.per_hit', 12));

        foreach ($this->config->array('keywords.words', []) as $word) {
            if (!is_string($word) || $word === '') {
                continue;
            }

            $count = substr_count($text, mb_strtolower($word));
            if ($count > 0) {
                $hits[$word] = $count;
            }
        }

        foreach ($this->config->array('keywords.patterns', []) as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            if (@preg_match($pattern, $text) === 1) {
                $hits['regex:' . $pattern] = 1;
            }
        }

        if ($hits === []) {
            return CheckOutcome::ham($this->name());
        }

        $total = array_sum($hits);
        $score = min($this->config->int('keywords.max_score', 90), $total * $perHit);

        return CheckOutcome::suspicious(
            $this->name(),
            max(1, $score),
            sprintf('%d spam keyword hit(s): %s', $total, implode(', ', array_keys($hits))),
            ['hits' => $hits],
        );
    }
}
