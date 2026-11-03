<?php

declare(strict_types=1);

namespace FormSpamChecker;

use FormSpamChecker\Token\FormToken;

/**
 * High-level helper for plain PHP forms: renders the protective fields and
 * verifies the submitted request.
 *
 *     $protector = new FormProtector($checker, $config);
 *     <form method="post">
 *         <?= $protector->fields('contact') ?>
 *         ...
 *     </form>
 *
 *     if ($protector->verifyRequest('contact')->isSpam()) { ... }
 *
 * The helper intentionally produces plain HTML with no CSS or JavaScript of its
 * own, so it fits any template and never conflicts with a site's assets.
 */
final class FormProtector
{
    public function __construct(
        private readonly SpamChecker $checker,
        private readonly Config $config,
    ) {
    }

    /**
     * Hidden inputs: honeypot plus, when enabled, the signed time-trap token.
     *
     * @param array{honeypot?: bool, token?: bool, container_style?: string, token_field?: string} $options
     */
    public function fields(string $formId = 'default', array $options = []): string
    {
        $config = $this->config->form($formId);
        $parts = [];

        $renderHoneypot = $options['honeypot'] ?? true;
        $honeypotFields = $config->array('honeypot.fields', []);

        if ($renderHoneypot && $config->bool('honeypot.enabled', true) && $honeypotFields !== []) {
            $style = $options['container_style']
                ?? 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden';

            $inputs = [];
            foreach ($honeypotFields as $field) {
                if (!is_string($field) || $field === '') {
                    continue;
                }

                $inputs[] = sprintf(
                    '<input type="text" name="%s" value="" tabindex="-1" autocomplete="off" aria-hidden="true">',
                    $this->escape($field),
                );
            }

            if ($inputs !== []) {
                $parts[] = sprintf(
                    '<div class="fs-hp" aria-hidden="true" style="%s">%s</div>',
                    $this->escape($style),
                    implode('', $inputs),
                );
            }
        }

        $renderToken = $options['token'] ?? true;

        if ($renderToken && $config->bool('time_trap.enabled', false)) {
            $tokenField = $options['token_field'] ?? $config->string('time_trap.field', '_fs_ts');
            $token = (new FormToken($config->secret()))->issue($formId);

            $parts[] = sprintf(
                '<input type="hidden" name="%s" value="%s">',
                $this->escape($tokenField),
                $this->escape($token),
            );
        }

        return implode("\n", $parts);
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
        return $this->verify($_POST, $formId, $context ?? Context::fromGlobals());
    }

    public function config(): Config
    {
        return $this->config;
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
