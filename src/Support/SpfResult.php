<?php

declare(strict_types=1);

namespace FormSpamChecker\Support;

/**
 * Outcome of one SPF evaluation (RFC 7208 §2.6, the "result" vocabulary).
 *
 * `TEMPERROR` is part of the vocabulary for contract completeness: the shipped
 * `ResolverInterface` implementations report DNS failure as an empty record set
 * instead of an error, so the evaluator can only produce it when a future
 * resolver grows an error channel.
 */
enum SpfResult: string
{
    case PASS = 'pass';
    case FAIL = 'fail';
    case SOFTFAIL = 'softfail';
    case NEUTRAL = 'neutral';
    case NONE = 'none';
    case PERMERROR = 'permerror';
    case TEMPERROR = 'temperror';
}
