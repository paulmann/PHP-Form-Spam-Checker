<?php

declare(strict_types=1);

namespace FormSpamChecker\Checks;

use FormSpamChecker\CheckInterface;
use FormSpamChecker\CheckResult;
use FormSpamChecker\Config;
use FormSpamChecker\Submission;
use FormSpamChecker\Support\Patterns;

/**
 * Bot detection by User-Agent.
 *
 * Blocks libraries, automation frameworks and scanners (hard Spam); an empty
 * User-Agent is suspicious by default. Real browser names are not on the list,
 * so a human with any mainstream browser always passes.
 */
final class UserAgentCheck implements CheckInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public function name(): string
    {
        return 'user_agent';
    }

    public function check(Submission $submission): CheckResult
    {
        if (!$this->config->bool('user_agent.enabled', true)) {
            return CheckResult::clean($this->name(), 'disabled');
        }

        $userAgent = trim($submission->context->userAgent);

        if ($userAgent === '') {
            if ($this->config->bool('user_agent.allow_empty', false)) {
                return CheckResult::clean($this->name(), 'empty user agent allowed');
            }

            return CheckResult::suspicious(
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
            if ($marker === '') {
                continue;
            }

            if (str_contains($haystack, mb_strtolower($marker))) {
                return CheckResult::spam(
                    $this->name(),
                    sprintf('automation marker "%s" in user agent', $marker),
                    ['marker' => $marker],
                    $this->config->int('user_agent.blocked_score', 100),
                );
            }
        }

        return CheckResult::clean($this->name());
    }
}
