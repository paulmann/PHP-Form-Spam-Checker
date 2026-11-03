<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;

/**
 * Spam-keyword scoring over the submitted text.
 *
 * Multibyte-aware and case-insensitive. Each keyword hit adds points; explicit
 * regular-expression patterns are supported for project-specific wording.
 * The check never returns a hard Spam status: keywords are a signal, and a
 * legitimate B2B message may mention an unfortunate word, so the pipeline
 * threshold decides.
 */
final class KeywordCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'keywords';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('keywords.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $exclude = $this->config->excludedFields();
        $scanFields = $this->config->array('keywords.scan_fields', []);

        $content = $submission->content($exclude);

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
            return CheckResult::clean($this->name(), 'no text to scan');
        }

        $text = mb_strtolower(implode("\n", $content));

        $hits = [];
        $perHit = max(1, $this->config->int('keywords.per_hit', 12));

        foreach ($this->config->array('keywords.words', []) as $word) {
            if (!is_string($word) || $word === '') {
                continue;
            }

            $needle = mb_strtolower($word);
            $count = substr_count($text, $needle);

            if ($count > 0) {
                $hits[$word] = $count;
            }
        }

        foreach ($this->config->array('keywords.patterns', []) as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            $result = @preg_match($pattern, $text);
            if ($result === 1) {
                $hits['regex:' . $pattern] = 1;
            }
        }

        if ($hits === []) {
            return CheckResult::clean($this->name());
        }

        $total = array_sum($hits);
        $score = min(
            $this->config->int('keywords.max_score', 90),
            $total * $perHit,
        );

        return CheckResult::suspicious(
            $this->name(),
            max(1, $score),
            sprintf('%d spam keyword hit(s): %s', $total, implode(', ', array_keys($hits))),
            ['hits' => $hits],
        );
    }
}
