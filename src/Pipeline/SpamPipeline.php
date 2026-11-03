<?php

declare(strict_types=1);

namespace FormSpamChecker\Pipeline;

use FormSpamChecker\Check\SpamCheckInterface;
use FormSpamChecker\Config;
use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\CheckStatus;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Data\Verdict;

/**
 * Ordered chain of checks (Chain of Responsibility).
 *
 * Cheap local checks are registered first; network checks last. With
 * `pipeline.stop_on_spam` enabled (default) the first hard SPAM stops the run,
 * which saves AbuseIPDB quota and DNS lookups. Any check that throws is
 * recorded as ERROR and the pipeline continues: a broken check never blocks a
 * form (fail open).
 */
final readonly class SpamPipeline
{
    /**
     * @param list<SpamCheckInterface> $checks
     */
    public function __construct(public array $checks = [])
    {
    }

    /**
     * Immutable append: returns a new pipeline with the check added.
     */
    #[\NoDiscard]
    public function add(SpamCheckInterface $check): self
    {
        $checks = $this->checks;
        $checks[] = $check;

        return new self($checks);
    }

    public function process(RequestData $data, Config $config): Verdict
    {
        $outcomes = [];
        $score = 0;
        $hardSpam = false;
        $stopOnSpam = $config->bool('pipeline.stop_on_spam', true);

        foreach ($this->checks as $check) {
            try {
                $outcome = $check->check($data);
            } catch (\Throwable $exception) {
                $outcome = CheckOutcome::error($check->name(), $exception->getMessage());
            }

            $outcomes[] = $outcome;
            $score += $outcome->score;

            if ($outcome->status === CheckStatus::SPAM) {
                $hardSpam = true;

                if ($stopOnSpam) {
                    break;
                }
            }
        }

        return Verdict::fromOutcomes($outcomes, $config, $hardSpam, $score);
    }
}
