<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Support\Patterns;

/**
 * Link counting: spam advertises URLs, shorteners and obfuscated domains.
 */
final readonly class LinkCheck implements SpamCheckInterface
{
    public function __construct(private Config $config) {}

    public function name(): string
    {
        return 'links';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->config->bool('links.enabled', true)) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $text = $data->text($this->config->excludedFields());

        if ($text === '') {
            return CheckOutcome::ham($this->name(), 'no text to scan');
        }

        $count = preg_match_all(Patterns::LINK_PATTERN, $text, $matches);
        $count = $count === false ? 0 : $count;

        $shorteners = [];
        foreach ($this->config->array('links.shorteners', []) as $shortener) {
            if (\is_string($shortener) && $shortener !== '') {
                $shorteners[] = mb_strtolower($shortener);
            }
        }

        $foundShorteners = [];
        $urls = $count > 0 ? $matches[0] : [];
        foreach ($urls as $url) {
            $host = $this->host($url);
            if ($host === null) {
                continue;
            }

            foreach ($shorteners as $shortener) {
                if ($host === $shortener || str_ends_with($host, '.' . $shortener)) {
                    $foundShorteners[] = $host;
                    break;
                }
            }
        }

        $obfuscated = 0;
        foreach (Patterns::obfuscatedLinkPatterns() as $pattern) {
            $result = @preg_match_all($pattern, $text, $obfuscatedMatches);
            if ($result !== false && $result > 0) {
                $obfuscated += $result;
            }
        }

        $max = max(0, $this->config->int('links.max', 2));
        $extra = max(0, $count - $max);

        $score = $extra * max(1, $this->config->int('links.score_per_extra', 15));
        if ($foundShorteners !== []) {
            $score += $this->config->int('links.shortener_score', 35);
        }
        if ($obfuscated > 0) {
            $score += $this->config->int('links.obfuscated_score', 25);
        }

        if ($score === 0) {
            return CheckOutcome::ham($this->name(), \sprintf('%d link(s), within the limit of %d', $count, $max));
        }

        $reason = [];
        if ($extra > 0) {
            $reason[] = \sprintf('%d links (max %d)', $count, $max);
        }
        if ($foundShorteners !== []) {
            $reason[] = 'URL shortener: ' . implode(', ', array_unique($foundShorteners));
        }
        if ($obfuscated > 0) {
            $reason[] = \sprintf('%d obfuscated link(s)', $obfuscated);
        }

        return CheckOutcome::suspicious(
            $this->name(),
            min(100, $score),
            implode('; ', $reason),
            [
                'links' => $count,
                'max' => $max,
                'shorteners' => array_values(array_unique($foundShorteners)),
                'obfuscated' => $obfuscated,
            ],
        );
    }

    private function host(string $url): ?string
    {
        $candidate = str_starts_with(mb_strtolower($url), 'www.') ? 'http://' . $url : $url;
        $parts = parse_url($candidate);

        if ($parts === false || !isset($parts['host'])) {
            return null;
        }

        return mb_strtolower($parts['host']);
    }
}
