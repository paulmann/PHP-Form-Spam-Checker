<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Support;

use FormSpamChecker\Context;
use FormSpamChecker\Submission;

trait BuildsSubmissions
{
    /**
     * @param array<string, mixed> $fields
     * @param array<string, mixed> $context
     */
    protected function submission(array $fields, array $context = [], string $formId = 'contact'): Submission
    {
        $context['now'] ??= 1_700_000_000;
        $context['ip'] ??= '203.0.113.10';
        $context['userAgent'] ??= 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

        return new Submission($fields, Context::fromArray($context), $formId);
    }
}
