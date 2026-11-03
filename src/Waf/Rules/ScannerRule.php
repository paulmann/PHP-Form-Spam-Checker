<?php

declare(strict_types=1);

namespace FormSpamChecker\Waf\Rules;

use FormSpamChecker\Waf\AbstractRule;
use FormSpamChecker\Waf\WafFinding;
use FormSpamChecker\Waf\WafRequest;

/**
 * Requests that probe for well-known vulnerable entry points.
 *
 * Two independent signals: a path that only scanners ask for (`/.env`,
 * `/wp-login.php`, `/cgi-bin`, ...) and a User-Agent that names an attack tool
 * (`sqlmap`, `nikto`, `nuclei`, ...). Both lists are configurable; neither is
 * matched against a bare browser User-Agent.
 *
 * High-entropy User-Agent scoring is intentionally not implemented: entropy is
 * not a reliable scanner signal and would block legitimate custom clients.
 */
final class ScannerRule extends AbstractRule
{
    protected const int DEFAULT_SEVERITY = 80;

    protected const bool DEFAULT_HARD = true;

    /** @var list<string> */
    private const array PATHS = [
        '/wp-admin',
        '/wp-login.php',
        '/wp-includes',
        '/xmlrpc.php',
        '/wp-config.php',
        '/wp-content/plugins',
        '/.env',
        '/.git',
        '/.svn',
        '/.aws',
        '/.ssh',
        '/.htaccess',
        '/phpmyadmin',
        '/pma',
        '/adminer',
        '/adminer.php',
        '/cgi-bin',
        '/cgi-sys',
        '/server-status',
        '/server-info',
        '/phpinfo.php',
        '/info.php',
        '/shell.php',
        '/webshell',
        '/actuator',
        '/jmx-console',
        '/manager/html',
        '/solr/admin',
    ];

    /** @var list<string> */
    private const array USER_AGENTS = [
        'sqlmap', 'nikto', 'acunetix', 'nessus', 'openvas', 'wpscan', 'dirbuster',
        'gobuster', 'wfuzz', 'ffuf', 'nuclei', 'masscan', 'nmap', 'zgrab', 'hydra',
        'whatweb', 'joomscan', 'droopescan', 'arachni', 'skipfish', 'w3af',
        'webinspect', 'appscan', 'burpsuite', 'metasploit', 'msfconsole',
        'owasp zap', 'dirsearch', 'feroxbuster', 'dirb', 'xray/', 'gospider',
        'hakrawler', 'waybackurls', 'subfinder', 'amass',
    ];

    public function name(): string
    {
        return 'scanner';
    }

    protected function defaultEnabled(): bool
    {
        return true;
    }

    protected function check(WafRequest $request): ?WafFinding
    {
        $paths = [...$this->listOption('paths', self::PATHS), ...$this->listOption('extra_paths', [])];
        $agents = [
            ...$this->listOption('user_agents', self::USER_AGENTS),
            ...$this->listOption('extra_user_agents', []),
        ];

        $path = $request->path();

        if (!$this->isAllowlisted($path)) {
            $match = $this->matchPath($path, $paths);
            if ($match !== null) {
                return $this->finding(
                    'scanner path requested',
                    'uri',
                    ['path' => $match, 'requested' => $path],
                );
            }
        }

        $userAgent = strtolower($request->userAgent());
        if ($userAgent !== '' && !$this->isAllowlisted($userAgent)) {
            foreach ($agents as $marker) {
                $marker = strtolower(trim($marker));
                if ($marker !== '' && str_contains($userAgent, $marker)) {
                    return $this->finding(
                        'scanner User-Agent detected',
                        'header.user-agent',
                        ['marker' => $marker],
                    );
                }
            }
        }

        return null;
    }

    /**
     * @param list<string> $needles
     */
    private function matchPath(string $path, array $needles): ?string
    {
        $candidates = $this->decodedVariants(strtolower($path));

        foreach ($needles as $needle) {
            $needle = strtolower(rtrim(trim($needle), '/'));

            if ($needle === '') {
                continue;
            }

            foreach ($candidates as $candidate) {
                if (
                    $candidate === $needle
                    || str_starts_with($candidate, $needle . '/')
                    || str_starts_with($candidate, $needle . '.')
                ) {
                    return $needle;
                }
            }
        }

        return null;
    }
}
