<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Bayes\Classifier;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;

/**
 * Bayesian classifier as a pipeline check.
 *
 * The check reads the already form-scoped configuration:
 *
 * - `bayes.enabled`       — off by default;
 * - `bayes.min_documents` — below this many trained documents the model
 *   abstains (`UNCERTAIN`, contributes 0);
 * - `bayes.threshold`     — spam probability that turns into a suspicion;
 * - `bayes.score_scale`   — score = round(probability * scale), capped at 100;
 * - `bayes.hard`          — when false (default) a match is only *suspicious*:
 *   a Bayesian model alone must not hard-block a submission. When true the
 *   outcome becomes a hard `SPAM` verdict.
 *
 * The classified text is the user content with technical fields removed
 * (`fields.exclude`, static/dynamic honeypot names, the JS challenge fields).
 */
final readonly class BayesCheck implements SpamCheckInterface
{
    public function __construct(
        private Classifier $classifier,
        private Config $config,
    ) {}

    public function name(): string
    {
        return 'bayes';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('bayes.enabled', false)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $minDocuments = max(0, $this->config->int('bayes.min_documents', 20));
        $documents = $this->classifier->documentCount();
        $trained = $this->classifier->isTrained();

        if (!$trained || $documents < $minDocuments) {
            return CheckOutcome::uncertain($this->name(), 'not enough training documents', [
                'documents' => $documents,
                'min_documents' => $minDocuments,
                'trained' => $trained,
            ]);
        }

        $text = $this->classifyText($data);

        if (trim($text) === '') {
            return new CheckOutcome($this->name(), CheckStatus::HAM, 0, 'no text to classify', [
                'probability' => 0.5,
                'threshold' => $this->threshold(),
                'documents' => $documents,
            ]);
        }

        $probability = $this->classifier->score($text);
        $threshold = $this->threshold();
        $scale = $this->config->int('bayes.score_scale', 100);

        $evidence = [
            'probability' => round($probability, 4),
            'threshold' => $threshold,
            'documents' => $documents,
        ];

        if ($probability < $threshold) {
            return new CheckOutcome(
                $this->name(),
                CheckStatus::HAM,
                0,
                \sprintf('bayesian spam probability %.3f < %.3f', $probability, $threshold),
                $evidence,
            );
        }

        $score = $this->score($probability, $scale);
        $reason = \sprintf('bayesian spam probability %.3f >= %.3f', $probability, $threshold);

        if ($this->config->bool('bayes.hard', false)) {
            return new CheckOutcome($this->name(), CheckStatus::SPAM, $score, $reason, $evidence);
        }

        return CheckOutcome::suspicious($this->name(), $score, $reason, $evidence);
    }

    private function threshold(): float
    {
        return min(1.0, max(0.0, $this->config->float('bayes.threshold', 0.92)));
    }

    private function score(float $probability, int $scale): int
    {
        $score = (int) round($probability * $scale);

        return max(1, min(100, $score));
    }

    /**
     * User content only: technical and behavioural fields never influence the
     * classifier, they are verified by their own checks.
     */
    private function classifyText(RequestData $data): string
    {
        $exclude = $this->config->excludedFields();
        $jsField = $this->config->string('behavioral.js_challenge.field', '_js');
        $exclude[] = $jsField;
        $exclude[] = $jsField . '_token';

        $content = $data->content($exclude);
        $prefix = $this->config->string('behavioral.honeypot.field_prefix', '_hp_');

        if ($prefix !== '') {
            foreach (array_keys($content) as $name) {
                if (str_starts_with($name, $prefix)) {
                    unset($content[$name]);
                }
            }
        }

        return implode("\n", $content);
    }
}
