<?php

declare(strict_types=1);

namespace FormSpamChecker\Support;

/**
 * Static signature tables used by the checks.
 *
 * They are plain arrays on purpose: a copy can be overridden per project via
 * configuration (extra markers, custom patterns) without subclassing a check.
 */
final class Patterns
{
    /**
     * Substrings that identify automation, scanners and HTTP libraries.
     *
     * Matched case-insensitively against the User-Agent. Real browser names are
     * deliberately absent: a browser UA must not block itself.
     *
     * @return list<string>
     */
    public static function userAgentMarkers(): array
    {
        return [
            // HTTP libraries and language runtimes
            'curl/', 'wget/', 'python-requests', 'python-urllib', 'aiohttp', 'httpx',
            'go-http-client', 'okhttp', 'java/', 'libwww-perl', 'perl/', 'php/',
            'ruby', 'node-fetch', 'axios/', 'guzzle', 'httpclient', 'restsharp',
            // Browser automation
            'selenium', 'webdriver', 'headlesschrome', 'headless', 'puppeteer',
            'playwright', 'phantomjs', 'slimerjs', 'nightmare', 'electron/',
            'splash', 'htmlunit', 'jsdom', 'zombie',
            // Scanners and exploitation tools
            'sqlmap', 'nikto', 'acunetix', 'nessus', 'openvas', 'wpscan', 'dirbuster',
            'gobuster', 'wfuzz', 'ffuf', 'nuclei', 'masscan', 'nmap', 'zgrab',
            'hydra', 'brutus', 'whatweb', 'joomscan', 'droopescan',
            // Crawlers and advertised bots
            'spider', 'crawler', 'bot/', 'bot ', 'scanner', 'harvester', 'crawl',
            'scrapy', 'mechanize', 'http://', 'compatible; ',
        ];
    }

    /**
     * Strong SQL-injection signatures: anywhere in user input they are spam.
     *
     * @return list<string>
     */
    public static function sqlStrongPatterns(): array
    {
        return [
            '/\bunion\b[\s\S]{0,30}\bselect\b/i',
            '/\bdrop\s+table\b/i',
            '/\btruncate\s+table\b/i',
            '/\binsert\s+into\b/i',
            '/\bdelete\s+from\b/i',
            '/\bxp_cmdshell\b/i',
            '/\binformation_schema\b/i',
            '/\bsleep\s*\(\s*\d+\s*\)/i',
            '/\bbenchmark\s*\(\s*\d+\s*,/i',
            '/\bwaitfor\s+delay\b/i',
            '/\bupdatexml\s*\(/i',
            '/\bextractvalue\s*\(/i',
            '/\bload_file\s*\(/i',
            '/\binto\s+outfile\b/i',
            '/\b(?:or|and)\s+\'?\d+\'?\s*=\s*\'?\d+\'?\b/i',
            '/\'\s*(?:or|and)\s*\'?\w*\'?\s*=\s*\'?\w+\'?/i',
            '/;\s*(?:drop|delete|truncate|alter|create)\s+/i',
        ];
    }

    /**
     * Weak SQL signatures: suspicious only, because they occur in normal prose.
     *
     * @return list<string>
     */
    public static function sqlWeakPatterns(): array
    {
        return [
            '/\bselect\b[\s\S]{0,40}\bfrom\b/i',
            '/\bunion\b/i',
            '/\bexec\s*\(/i',
            '/\bdeclare\s+@/i',
            '/\bchar\s*\(\s*\d+/i',
        ];
    }

    /**
     * Strong XSS signatures: executable markup and JavaScript URIs.
     *
     * @return list<string>
     */
    public static function xssStrongPatterns(): array
    {
        return [
            '/<\s*script\b/i',
            '/<\s*iframe\b/i',
            '/<\s*object\b/i',
            '/<\s*embed\b/i',
            '/<\s*svg\b[^>]*\bon\w+\s*=/i',
            '/\bjavascript\s*:/i',
            '/\bvbscript\s*:/i',
            '/\bon(?:error|load|click|mouseover|mouseout|focus|blur|submit|change|input|animationstart|toggle)\s*=/i',
            '/\bdocument\s*\.\s*(?:cookie|location|write|domain)\b/i',
            '/\bwindow\s*\.\s*location\b/i',
            '/\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)/i',
            '/\bdata\s*:\s*text\/html/i',
            '/<\s*img\b[^>]*\bonerror\s*=/i',
        ];
    }

    /**
     * Weak XSS signatures: encoded payloads and dangerous attributes.
     *
     * @return list<string>
     */
    public static function xssWeakPatterns(): array
    {
        return [
            '/&#(?:0*60|x0*3c|0*62|x0*3e);?/i',
            '/%\s*3c\s*script/i',
            '/<\s*(?:style|link|meta|base)\b[^>]*(?:http-equiv|expression|url\s*\()/i',
            '/(?:srcdoc|formaction|onpointer|ontouch|onfocusin)\s*=/i',
        ];
    }

    /**
     * Disposable / throwaway e-mail domains, matched by suffix.
     *
     * @return list<string>
     */
    public static function disposableDomains(): array
    {
        return [
            'mailinator.com', 'mailinator.net', 'tempmail.com', 'temp-mail.org',
            'temp-mail.io', 'guerrillamail.com', 'guerrillamail.info', 'guerrillamail.biz',
            'guerrillamail.de', 'guerrillamail.net', 'guerrillamail.org', 'yopmail.com',
            'yopmail.fr', 'yopmail.net', 'trashmail.com', 'trashmail.net', 'trashmail.org',
            '10minutemail.com', '10minutemail.net', '10minutemail.org', 'dispostable.com',
            'fakeinbox.com', 'fakemailgenerator.com', 'maildrop.cc', 'throwawaymail.com',
            'getnada.com', 'nada.email', 'emailondeck.com', 'moakt.com', 'mintemail.com',
            'spam4.me', 'mytemp.email', 'mailnesia.com', 'mailcatch.com', 'mohmal.com',
            'burnermail.io', 'tempail.com', 'inboxbear.com', 'tempr.email', 'discard.email',
            'discardmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
            'spamgourmet.com', 'spamgourmet.net', 'mailnull.com', 'spamex.com',
            'tempinbox.com', 'tempinbox.co.uk', 'emailfake.com', 'generator.email',
            'crazymailing.com', 'mailsac.com', 'mail-temp.com', 'temp-mail.ru',
            'tempmail.ru', 'tempmailo.com', 'luxusmail.org', 'mailpoof.com',
            'mytempmail.com', 'tempemail.net', 'tempemail.com', 'throwaway.email',
            'mailtemp.info', 'mail-temp.de', 'wegwerfemail.de', 'trashmail.de',
            'emailtemporario.com.br', 'correotemporario.com', 'throwaway.email',
        ];
    }

    /**
     * URL pattern used by the link check (http/https and bare www).
     */
    public const string LINK_PATTERN = '~(?:https?://|www\.)[^\s<>"\'\x00-\x1F]+~iu';

    /**
     * Obfuscated link spellings ("hxxp://", "site [.] ru", "site (dot) ru").
     *
     * @return list<string>
     */
    public static function obfuscatedLinkPatterns(): array
    {
        return [
            '/\bhxxps?:\/\//i',
            '/\b\w+\s*\[\.\]\s*\w+/iu',
            '/\b\w+\s*\(\s*dot\s*\)\s*\w+/iu',
            '/\b\w+\s+dot\s+\w+\s*\.\s*(?:ru|com|net|org)\b/iu',
        ];
    }
}
