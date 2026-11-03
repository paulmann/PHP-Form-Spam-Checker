<?php

declare(strict_types=1);

namespace FormSpamChecker\Check;

use FormSpamChecker\Data\CheckOutcome;
use FormSpamChecker\Data\RequestData;
use FormSpamChecker\Security\AutoBan;

/**
 * First check in the pipeline: a banned IP is hard spam.
 *
 * The ban is maintained by {@see AutoBan} from previous spam verdicts and WAF
 * blocks. A banned IP is rejected before any expensive check runs, so a
 * persistent attacker costs one storage lookup per request.
 */
final readonly class BanCheck implements SpamCheckInterface
{
    public function __construct(private AutoBan $autoBan) {}

    public function name(): string
    {
        return 'autoban';
    }

    public function check(RequestData $data): CheckOutcome
    {
        if (!$this->autoBan->enabled()) {
            return CheckOutcome::ham($this->name(), 'disabled');
        }

        $ip = $data->ip;

        if ($ip === '') {
            return CheckOutcome::uncertain($this->name(), 'no client ip');
        }

        if (!$this->autoBan->isBanned($ip)) {
            return CheckOutcome::ham($this->name(), 'ip is not banned');
        }

        return CheckOutcome::spam(
            $this->name(),
            'client ip is banned by the auto-ban',
            ['ip' => $ip],
            100,
        );
    }
}
