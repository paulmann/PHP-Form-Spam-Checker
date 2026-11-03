<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Operating-system command injection signatures.
 *
 * Patterns deliberately require shell syntax around the command name: a
 * semicolon in Russian or English prose ("Спасибо; ответьте, пожалуйста") or a
 * Markdown table row ("| id | name |") must not block the request. A pipe into
 * an interpreter, a command substitution, a command followed by an absolute
 * path or a Windows shell invocation are attack shapes, not prose.
 */
final class CommandInjectionRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 90;

    protected const bool DEFAULT_HARD = true;

    /** @var list<string> */
    private const array PATTERNS = [
        // Shell chaining into an executable. The pipe is intentionally absent
        // here: it is the Markdown table separator and would match "| id |".
        '/[;&]\s*(?:cat|tac|head|tail|less|more|ls|dir|wget|curl|nc|netcat|ncat|bash|sh|zsh|ksh|dash'
            . '|python[0-9.]*|perl|ruby|php|node|chmod|chown|whoami|id|uname|hostname|ps|kill|rm|mv'
            . '|cp|echo|sleep|nslookup|dig|telnet|ssh|scp|env|export|printenv)\b/i',
        // Piping into a shell or a raw network tool.
        '/\|\s*(?:sh|bash|zsh|ksh|dash|nc|netcat|ncat|cat|perl|python[0-9.]*|php|ruby)\b/i',
        // Command substitution that actually contains a command.
        '/\$\(\s*(?:cat|tac|ls|dir|wget|curl|nc|netcat|bash|sh|zsh|id|whoami|uname|hostname|rm'
            . '|chmod|chown|python[0-9.]*|perl|php|sleep|nslookup|dig)\b[^)\r\n]{0,200}\)/i',
        // A command with an absolute path argument (cat /etc/passwd).
        '/\b(?:cat|tac|wget|curl|nc|bash|sh|python[0-9.]*|perl|php)\s+\/(?:etc|bin|usr|tmp|var|proc'
            . '|dev|home|opt|srv|boot)\/[^\s;|&"\'<>]{1,200}/i',
        // Windows shell invocation and drive paths.
        '/\b(?:cmd(?:\.exe)?\s+\/[ck]|powershell(?:\.exe)?\s+(?:-c|-command)'
            . '|pwsh\s+(?:-c|-command)|wscript|cscript)\b/i',
        '/\b(?:type|dir|copy|del|move)\s+[a-z]:\\\\/i',
    ];

    public function name(): string
    {
        return 'command_injection';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $patterns = $this->patternList('patterns', self::PATTERNS);

        if ($patterns === []) {
            return null;
        }

        foreach ($this->requestValues($request) as $location => $text) {
            if ($this->isAllowlisted($text)) {
                continue;
            }

            $hit = $this->firstMatch($patterns, $text);
            if ($hit === null) {
                continue;
            }

            return $this->finding('OS command injection signature detected', $location, $hit);
        }

        return null;
    }
}
