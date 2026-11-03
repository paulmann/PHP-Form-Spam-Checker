<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Behavioral\Honeypot;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;

/**
 * Behavioural honeypot check with hour-rotating field names.
 *
 * Dynamic mode (`behavioral.honeypot.dynamic`, the default):
 *
 * - a filled field whose name matches the current or previous hour bucket for
 *   the submitted form is conclusive evidence of automation → hard `SPAM`;
 * - a submission that does not contain either expected field at all is
 *   suspicious (`behavioral.honeypot.missing_score`, default 10): a browser
 *   always posts the rendered form, a blind bot posts only its own fields;
 * - a secret shorter than 16 characters is a configuration error → `ERROR`
 *   (fail open, contributes 0).
 *
 * Static mode (`dynamic = false`) verifies the configured list of honeypot
 * field names (`behavioral.honeypot.static`, falling back to the 1.x
 * `honeypot.fields` list): a filled name is a hard `SPAM`, a missing or empty
 * one is `HAM` — static names are public knowledge, so "missing" proves nothing.
 */
final readonly class DynamicHoneypotCheck implements SpamCheckInterface
{
    private const VALUE_PREVIEW_LENGTH = 80;

    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'dynamic_honeypot';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('behavioral.honeypot.dynamic', true)) {
            return $this->checkStatic($data);
        }

        $honeypot = new Honeypot($this->config);

        if (!$honeypot->isConfigured()) {
            return CheckOutcome::error(
                $this->name(),
                \sprintf(
                    'behavioral.honeypot.secret must be at least %d characters to use the dynamic honeypot',
                    Honeypot::SECRET_MIN_LENGTH,
                ),
            );
        }

        $filled = $honeypot->verify($data, $data->formId);

        if ($filled !== null) {
            return new CheckOutcome(
                $this->name(),
                CheckStatus::SPAM,
                100,
                'honeypot field filled: ' . $filled,
                [
                    'field' => $filled,
                    'value' => mb_substr($data->field($filled), 0, self::VALUE_PREVIEW_LENGTH),
                ],
            );
        }

        $candidates = $honeypot->candidates($data->formId, $data->timestamp());
        $present = false;

        foreach ($candidates as $candidate) {
            if ($data->hasField($candidate)) {
                $present = true;
                break;
            }
        }

        if (!$present) {
            return CheckOutcome::suspicious(
                $this->name(),
                $this->config->int('behavioral.honeypot.missing_score', 10),
                'expected dynamic honeypot field is missing',
                ['expected' => $candidates],
            );
        }

        return CheckOutcome::ham($this->name(), 'dynamic honeypot empty');
    }

    private function checkStatic(RequestData $data): CheckOutcome
    {
        $honeypot = new Honeypot($this->config);
        $fields = $honeypot->staticFields();

        if ($fields === []) {
            return CheckOutcome::ham($this->name(), 'static honeypot not configured');
        }

        $filled = [];

        foreach ($fields as $field) {
            if ($data->hasField($field) && $data->field($field) !== '') {
                $filled[$field] = mb_substr($data->field($field), 0, self::VALUE_PREVIEW_LENGTH);
            }
        }

        if ($filled === []) {
            return CheckOutcome::ham($this->name(), 'static honeypot empty');
        }

        return new CheckOutcome(
            $this->name(),
            CheckStatus::SPAM,
            100,
            'static honeypot field filled: ' . implode(', ', array_keys($filled)),
            ['fields' => $filled],
        );
    }
}
