<?php

declare(strict_types=1);

namespace FormSpamChecker;

/**
 * Runs checks in order and aggregates their results.
 *
 * A failing check must never break a form: exceptions are caught and recorded
 * as a clean result carrying the error, so the submission still reaches the
 * application (fail open). The error is part of the check list, which makes it
 * visible in logs and in the verdict array.
 */
final class Pipeline
{
    /**
     * @param list<CheckInterface> $checks
     */
    public function __construct(private readonly array $checks)
    {
    }

    /**
     * @return list<CheckInterface>
     */
    public function checks(): array
    {
        return $this->checks;
    }

    public function run(Submission $submission, Config $config): Verdict
    {
        $results = [];

        foreach ($this->checks as $check) {
            try {
                $results[] = $check->check($submission);
            } catch (\Throwable $exception) {
                $results[] = CheckResult::clean(
                    $check->name(),
                    'check error (fail open): ' . $exception->getMessage(),
                );
            }
        }

        return Verdict::fromResults($results, $config);
    }
}
