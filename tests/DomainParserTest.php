<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter\Tests;

use BahriCanli\DomainHunter\DomainParser;
use BahriCanli\DomainHunter\WhoisService;
use PHPUnit\Framework\TestCase;

final class DomainParserTest extends TestCase
{
    private DomainParser $parser;

    protected function setUp(): void
    {
        $this->parser = new DomainParser(new WhoisService());
    }

    /**
     * @dataProvider validDomainProvider
     */
    public function testParsesValidDomains(string $input, string $expectedLabel, string $expectedTld): void
    {
        $result = $this->parser->parse($input);

        self::assertSame($expectedLabel, $result['label']);
        self::assertSame($expectedTld, $result['tld']);
    }

    public static function validDomainProvider(): array
    {
        return [
            'plain TLD'                          => ['example.com', 'example', 'com'],
            'subdomain of plain TLD'              => ['blog.example.com', 'example', 'com'],
            'deeply nested subdomain, plain TLD'  => ['a.b.blog.example.com', 'example', 'com'],
            'compound TLD'                        => ['example.co.uk', 'example', 'co.uk'],
            'subdomain of compound TLD'           => ['blog.example.co.uk', 'example', 'co.uk'],
            'deeply nested subdomain, compound'   => ['a.b.blog.example.co.uk', 'example', 'co.uk'],
            'Turkish compound TLD'                => ['example.com.tr', 'example', 'com.tr'],
            'subdomain of Turkish compound TLD'   => ['blog.example.com.tr', 'example', 'com.tr'],
            'uppercase input is lowercased'       => ['EXAMPLE.COM', 'example', 'com'],
            'leading/trailing whitespace trimmed' => ['  example.com  ', 'example', 'com'],
            'www. prefix is stripped'             => ['www.example.com', 'example', 'com'],
        ];
    }

    public function testThrowsForSingleLabelInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid domain format');

        $this->parser->parse('not-a-domain');
    }

    public function testThrowsForLabelTooShort(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Domain label is too short');

        $this->parser->parse('a.b');
    }

    public function testThrowsForInvalidCharactersInLabel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Domain label contains invalid characters');

        $this->parser->parse('under_score.com');
    }

    public function testToPunycodePassesAsciiThrough(): void
    {
        self::assertSame('example', $this->parser->toPunycode('example'));
    }

    public function testToPunycodeConvertsUnicodeLabel(): void
    {
        self::assertSame('xn--r8jz45g', $this->parser->toPunycode('例え'));
    }
}
