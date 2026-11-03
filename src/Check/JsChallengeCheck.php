<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Behavioral\JsChallenge;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;

/**
 * Verifies the answer and the signed token of the JavaScript challenge.
 *
 * Configuration (`behavioral.js_challenge.*`):
 *
 * - `enabled`       — off by default, then the check is `HAM`;
 * - `field`         — answer field name (default `_js`); the token lives in
 *   `<field>_token`;
 * - `missing_score` — suspicion score for a missing or invalid answer
 *   (default 15; never a hard SPAM: a bot without JS is suspicious, not proven
 *   to be spam, and a broken deployment must fail open).
 *
 * A short or missing secret is reported as `ERROR` (fail open).
 */
final readonly class JsChallengeCheck implements SpamCheckInterface
{
    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'js_challenge';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('behavioral.js_challenge.enabled', false)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $challenge = new JsChallenge($this->config);
        $error = $challenge->configError();

        if ($error !== null) {
            return CheckOutcome::error($this->name(), $error);
        }

        $answer = $data->field($challenge->field());
        $token = $data->field($challenge->tokenField());
        $evidence = [
            'field' => $challenge->field(),
            'token_field' => $challenge->tokenField(),
            'answer_present' => $answer !== '',
            'token_present' => $token !== '',
        ];

        if ($answer === '' || $token === '') {
            return CheckOutcome::suspicious(
                $this->name(),
                $this->missingScore(),
                'js challenge missing',
                $evidence,
            );
        }

        if (!$challenge->verify($data, $data->formId)) {
            return CheckOutcome::suspicious(
                $this->name(),
                $this->missingScore(),
                'js challenge invalid or expired',
                $evidence,
            );
        }

        return CheckOutcome::ham($this->name(), 'js challenge passed');
    }

    private function missingScore(): int
    {
        return max(1, min(100, $this->config->int('behavioral.js_challenge.missing_score', 15)));
    }
}
