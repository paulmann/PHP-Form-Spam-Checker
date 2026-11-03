<?php

declare(strict_types=1);

namespace FormSpamChecker\Tests\Unit\Network;

use FormSpamChecker\Support\EmailAddress;

final class EmailAddressTest extends NetworkTestCase
{
    public function testBareAddressIsNormalisedToLowerCase(): void
    {
        self::assertSame('user@example.com', EmailAddress::fromValue('User@Example.COM'));
    }

    public function testDisplayNameFormIsUnwrapped(): void
    {
        self::assertSame('user@example.com', EmailAddress::fromValue('John Doe <user@example.com>'));
        self::assertSame('user@example.com', EmailAddress::fromValue('"Doe, John" <user@example.com>'));
    }

    public function testMailtoPrefixIsAccepted(): void
    {
        self::assertSame('user@example.com', EmailAddress::fromValue('mailto:user@example.com'));
    }

    public function testInvalidValuesBecomeEmptyStrings(): void
    {
        self::assertSame('', EmailAddress::fromValue(''));
        self::assertSame('', EmailAddress::fromValue('   '));
        self::assertSame('', EmailAddress::fromValue('not an address'));
        self::assertSame('', EmailAddress::fromValue('user@@example.com'));
        self::assertSame('', EmailAddress::fromValue('<user@example.com'));
    }

    public function testDomainIsExtractedFromEveryAcceptedForm(): void
    {
        self::assertSame('example.com', EmailAddress::domain('user@example.com'));
        self::assertSame('example.com', EmailAddress::domain('John <USER@Example.com>'));
        self::assertSame('', EmailAddress::domain('user@'));
        self::assertSame('', EmailAddress::domain('no-at-sign'));
    }

    public function testDomainsForFieldsSkipsInvalidAndUnknownFields(): void
    {
        $data = $this->request(fields: [
            'email' => 'John <user@Example.com>',
            'personalEmail' => 'not-an-address',
            'other' => 'someone@example.org',
        ]);

        $domains = EmailAddress::domainsForFields($data, ['email', 'personalEmail', 'missing', 42]);

        self::assertSame(['email' => 'example.com'], $domains);
    }

    public function testDomainsForFieldsKeepsOneEntryPerField(): void
    {
        $data = $this->request(fields: [
            'email' => 'a@example.org',
            'second' => 'b@example.org',
        ]);

        $domains = EmailAddress::domainsForFields($data, ['email', 'second']);

        self::assertSame(['email' => 'example.org', 'second' => 'example.org'], $domains);
    }
}
