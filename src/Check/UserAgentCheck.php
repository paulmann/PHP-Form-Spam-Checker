<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Support\Patterns;

/**
 * Bot detection by User-Agent: automation libraries, headless browsers and
 * scanners are hard Spam; an empty UA is suspicious unless allowed.
 */
final readonly class UserAgentCheck implements SpamCheckInterface
{
    public function __construct(private Config $config)
    {
    }

    public function name(): string
    {
        return 'user_agent';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('user_agent.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $userAgent = trim($data->userAgent());

        if ($userAgent === '') {
            if ($this->config->bool('user_agent.allow_empty', false)) {
                return CheckOutcome::ham($this->name(), 'empty user agent allowed');
            }

            return CheckOutcome::suspicious(
                $this->name(),
                $this->config->int('user_agent.empty_score', 40),
                'empty user agent',
            );
        }

        $haystack = mb_strtolower($userAgent);
        $markers = Patterns::userAgentMarkers();

        foreach ($this->config->array('user_agent.extra_blocklist', []) as $extra) {
            if (is_string($extra) && $extra !== '') {
                $markers[] = $extra;
            }
        }

        foreach ($markers as $marker) {
            if ($marker !== '' && str_contains($haystack, mb_strtolower($marker))) {
                return new CheckOutcome(
                    $this->name(),
                    CheckStatus::SPAM,
                    $this->config->int('user_agent.blocked_score', 100),
                    sprintf('automation marker "%s" in user agent', $marker),
                    ['marker' => $marker],
                );
            }
        }

        return CheckOutcome::ham($this->name());
    }
}
