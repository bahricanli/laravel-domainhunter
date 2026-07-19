<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter\Tests;

use BahriCanli\DomainHunter\WhoisResult;
use BahriCanli\DomainHunter\WhoisService;
use PHPUnit\Framework\TestCase;

final class WhoisServiceTest extends TestCase
{
    private WhoisService $whois;

    protected function setUp(): void
    {
        $this->whois = new WhoisService();
    }

    public function testCompoundTldsOnlyContainsDottedTlds(): void
    {
        $compound = $this->whois->compoundTlds();

        self::assertNotEmpty($compound);
        self::assertContains('co.uk', $compound);
        self::assertContains('com.tr', $compound);
        foreach ($compound as $tld) {
            self::assertStringContainsString('.', $tld);
        }
        self::assertNotContains('com', $compound);
    }

    public function testLookupThrowsForUnsupportedTld(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('TLD .doesnotexist is not supported.');

        $this->whois->lookup('example', 'doesnotexist');
    }

    public function testParseGenericExtractsCoreFields(): void
    {
        $raw = <<<RAW
        % This is a comment line, ignored
        Domain Name: EXAMPLE.COM
        Registrar: Example Registrar, Inc.
        Registrar WHOIS Server: whois.example-registrar.com
        Creation Date: 1997-08-14T04:00:00Z
        Registry Expiry Date: 2028-08-13T04:00:00Z
        Updated Date: 2024-08-14T07:01:31Z
        Name Server: NS1.EXAMPLE.COM
        Name Server: NS2.EXAMPLE.COM
        Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        RAW;

        $result = $this->invokeParser('parseGeneric', $raw);

        self::assertInstanceOf(WhoisResult::class, $result);
        self::assertSame('EXAMPLE.COM', $result->domainName);
        self::assertSame('Example Registrar, Inc.', $result->registrar);
        self::assertSame('whois.example-registrar.com', $result->whoisServer);
        self::assertSame('1997-08-14', $result->creationDate);
        self::assertSame('2028-08-13', $result->expirationDate);
        self::assertSame('2024-08-14', $result->updatedDate);
        self::assertSame(['ns1.example.com', 'ns2.example.com'], $result->nameServers);
        self::assertSame(['clientTransferProhibited'], $result->statuses);
    }

    public function testParseGenericIgnoresBlankAndCommentLines(): void
    {
        $raw = <<<RAW
        % comment
        > another comment style

        Domain Name: EXAMPLE.NET
        RAW;

        $result = $this->invokeParser('parseGeneric', $raw);

        self::assertSame('EXAMPLE.NET', $result->domainName);
    }

    public function testParseTrExtractsFieldsFromSectionedFormat(): void
    {
        $raw = <<<RAW
        ** Domain Name: example.com.tr

        ** Registrant:
        \tOrganization Name : Example A.S.

        ** Registrar:
        \tOrganization Name : Example Registrar

        ** Domain Servers:
        ns1.example.com.tr
        ns2.example.com.tr

        ** Additional Info:
        Created on..............: 2010-Jan-05.
        Expires on...............: 2027-Jan-05.
        Updated on...............: 2024-Jan-05.
        RAW;

        $result = $this->invokeParser('parseTr', $raw);

        self::assertSame('EXAMPLE.COM.TR', $result->domainName);
        self::assertSame('Example Registrar', $result->registrar);
        self::assertSame(['ns1.example.com.tr', 'ns2.example.com.tr'], $result->nameServers);
        self::assertSame('2010-01-05', $result->creationDate);
        self::assertSame('2027-01-05', $result->expirationDate);
        self::assertSame('2024-01-05', $result->updatedDate);
    }

    public function testParseBeExtractsNestedRegistrarAndBareNameServers(): void
    {
        // Regression test for the .be format fixed in commit 3fc6c87: nested
        // "Registrar:\n\tName:\t..." blocks and bare "host (ip)" name server
        // lines with no colon, which the generic parser can't handle.
        $raw = "Domain:\texample.be\n"
            . "Status:\tNOT AVAILABLE\n"
            . "Registered:\tSun Sep 23 2007\n"
            . "Registrar:\n"
            . "\tName:\tExample Registrar BV\n"
            . "\tWebsite:\thttps://example-registrar.example\n"
            . "Nameservers:\n"
            . "\tns1.example.be (1.2.3.4)\n"
            . "\tns2.example.be (5.6.7.8)\n";

        $result = $this->invokeParser('parseBe', $raw);

        self::assertSame('EXAMPLE.BE', $result->domainName);
        self::assertSame(['NOT AVAILABLE'], $result->statuses);
        // Guards against the year-stripping regression: a bare trailing year
        // ("...2007") must survive parseDate(), not be treated as a timezone
        // token and dropped.
        self::assertSame('2007-09-23', $result->creationDate);
        self::assertSame('Example Registrar BV', $result->registrar);
        self::assertSame('https://example-registrar.example', $result->referralUrl);
        self::assertSame(['ns1.example.be', 'ns2.example.be'], $result->nameServers);
    }

    /**
     * @dataProvider dateProvider
     */
    public function testParseDateNormalizesToYmd(string $input, ?string $expected): void
    {
        $method = new \ReflectionMethod(WhoisService::class, 'parseDate');
        $method->setAccessible(true);

        self::assertSame($expected, $method->invoke($this->whois, $input));
    }

    public static function dateProvider(): array
    {
        return [
            'ISO 8601 with time and timezone marker' => ['1997-08-14T04:00:00Z', '1997-08-14'],
            'weekday-month-day-year with trailing year kept' => ['Sun Sep 23 2007', '2007-09-23'],
            'trailing timezone name stripped'          => ['2024-08-14 07:01:31 UTC', '2024-08-14'],
            'empty string returns null'                => ['', null],
        ];
    }

    private function invokeParser(string $method, string $raw): WhoisResult
    {
        $reflection = new \ReflectionMethod(WhoisService::class, $method);
        $reflection->setAccessible(true);

        /** @var WhoisResult $result */
        $result = $reflection->invoke($this->whois, $raw);

        return $result;
    }
}
