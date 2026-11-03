<?php

declare(strict_types=1);

namespace FormSpamChecker\Dns;

/**
 * DNS resolver abstraction used by DNSBL, SPF and DMARC checks.
 *
 * Implementations may cache aggressively: a form submission must never wait on
 * more than one DNS round-trip per name. Checks receive this interface and are
 * tested against a fake resolver, never against the network.
 */
interface ResolverInterface
{
    /**
     * @return list<string> TXT record values (quoted parts joined)
     */
    public function txt(string $name): array;

    /**
     * @return list<string> A record addresses
     */
    public function a(string $name): array;

    /**
     * @return list<string> MX host names, lower-case, without trailing dot
     */
    public function mx(string $name): array;
}
