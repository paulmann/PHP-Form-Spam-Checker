<?php

declare(strict_types=1);

namespace FormSpamChecker;

use FormSpamChecker\Behavioral\Honeypot;
use FormSpamChecker\Behavioral\JsChallenge;
use FormSpamChecker\Data\Verdict;
use FormSpamChecker\Token\FormToken;
use Throwable;

/**
 * High-level helper for plain PHP forms: renders the protective fields and
 * verifies the submitted request.
 *
 *     $protector = new FormProtector($checker, $config);
 *     <form method="post">
 *         <?= $protector->fields('contact') ?>
 *     </form>
 *     $verdict = $protector->verifyRequest('contact');
 *
 * The helper produces plain HTML without CSS frameworks or external scripts.
 */
final class FormProtector
{
    public function __construct(
        private readonly SpamChecker $checker,
        private readonly Config $config,
    ) {}

    /**
     * Hidden inputs: honeypot (static or dynamic), signed time-trap token and,
     * when enabled, the JS challenge.
     *
     * @param array{honeypot?: bool, token?: bool, js?: bool, container_style?: string, token_field?: string} $options
     */
    public function fields(string $formId = 'default', array $options = []): string
    {
        $config = $this->config->form($formId);
        $parts = [];

        if (($options['honeypot'] ?? true) && $config->bool('honeypot.enabled', true)) {
            $parts[] = $this->honeypotFields($config, $formId, $options);
        }

        if (($options['token'] ?? true) && $config->bool('time_trap.enabled', false)) {
            $tokenField = $options['token_field'] ?? $config->string('time_trap.field', '_fs_ts');
            $token = (new FormToken($config->secret()))->issue($formId);

            $parts[] = \sprintf(
                '<input type="hidden" name="%s" value="%s">',
                $this->escape($tokenField),
                $this->escape($token),
            );
        }

        if (($options['js'] ?? true) && $config->bool('behavioral.js_challenge.enabled', false)
            && class_exists(JsChallenge::class)
        ) {
            $parts[] = $this->jsChallengeFields($config, $formId);
        }

        return implode("\n", array_filter($parts, static fn(string $part): bool => $part !== ''));
    }

    /**
     * Verify already-extracted fields.
     *
     * @param array<string, mixed> $fields
     */
    public function verify(array $fields, string $formId = 'default', ?Context $context = null): Verdict
    {
        return $this->checker->check($fields, $context, $formId);
    }

    /**
     * Verify the current POST request using the request superglobals.
     */
    public function verifyRequest(string $formId = 'default', ?Context $context = null): Verdict
    {
        /** @var array<string, mixed> $fields */
        $fields = $_POST;

        return $this->verify($fields, $formId, $context ?? Context::fromGlobals());
    }

    public function config(): Config
    {
        return $this->config;
    }

    /**
     * @param array{honeypot?: bool, token?: bool, js?: bool, container_style?: string, token_field?: string} $options
     */
    private function honeypotFields(Config $config, string $formId, array $options): string
    {
        $style = $options['container_style']
            ?? 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden';

        $dynamic = $config->bool('behavioral.honeypot.dynamic', true)
            && $config->string('behavioral.honeypot.secret') !== ''
            && class_exists(Honeypot::class);

        if ($dynamic) {
            $honeypot = new Honeypot($config);
            $names = [$honeypot->fieldName($formId)];
        } else {
            $names = [];
            foreach ($config->array('honeypot.fields', []) as $field) {
                if (\is_string($field) && $field !== '') {
                    $names[] = $field;
                }
            }
        }

        if ($names === []) {
            return '';
        }

        $inputs = [];
        foreach ($names as $name) {
            $inputs[] = \sprintf(
                '<input type="text" name="%s" value="" tabindex="-1" autocomplete="off" aria-hidden="true">',
                $this->escape($name),
            );
        }

        return \sprintf(
            '<div class="fs-hp" aria-hidden="true" style="%s">%s</div>',
            $this->escape($style),
            implode('', $inputs),
        );
    }

    private function jsChallengeFields(Config $config, string $formId): string
    {
        try {
            $challenge = new JsChallenge($config);

            if (!$challenge->isConfigured()) {
                return '';
            }

            $issued = $challenge->issue($formId);
            $field = $challenge->field();

            return \sprintf(
                '<input type="hidden" name="%s" value="" data-fs-js="1">'
                . '<input type="hidden" name="%s" value="%s">'
                . $challenge->inlineScript($formId),
                $this->escape($field),
                $this->escape($challenge->tokenField()),
                $this->escape($issued['token']),
            );
        } catch (Throwable) {
            // A misconfigured challenge must never break the rendering of a form.
            return '';
        }
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
