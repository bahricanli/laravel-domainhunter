<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter\Tests;

use BahriCanli\DomainHunter\PublicSuffixList;
use PHPUnit\Framework\TestCase;

final class PublicSuffixListTest extends TestCase
{
    private PublicSuffixList $psl;

    protected function setUp(): void
    {
        $this->psl = new PublicSuffixList();
    }

    /**
     * @dataProvider splitProvider
     * @param string[] $labels
     */
    public function testSplit(array $labels, string $expectedLabel, string $expectedTld): void
    {
        $result = $this->psl->split($labels);

        self::assertSame($expectedLabel, $result['label']);
        self::assertSame($expectedTld, $result['tld']);
    }

    public static function splitProvider(): array
    {
        return [
            'plain gTLD'                       => [['example', 'com'], 'example', 'com'],
            'subdomain of plain gTLD'           => [['blog', 'example', 'com'], 'example', 'com'],
            'deeply nested, plain gTLD'         => [['a', 'b', 'blog', 'example', 'com'], 'example', 'com'],
            'listed compound TLD (co.uk)'       => [['example', 'co', 'uk'], 'example', 'co.uk'],
            'subdomain of listed compound'      => [['blog', 'example', 'co', 'uk'], 'example', 'co.uk'],
            'directly registrable ccTLD (uk)'   => [['example', 'uk'], 'example', 'uk'],
            // Regression case from the Codex review on PR #1: "br" alone is
            // a known TLD, so the old hand-curated-list guess treated "com"
            // as the label and "br" as the TLD instead of recognizing
            // "com.br" as the actual (but unlisted-in-WhoisService) suffix.
            'unlisted compound TLD (com.br)'    => [['example', 'com', 'br'], 'example', 'com.br'],
            'subdomain of unlisted compound'    => [['blog', 'example', 'com', 'br'], 'example', 'com.br'],
            // "*.ck" wildcard rule with a "!www.ck" exception carving that
            // specific string back out as directly registrable.
            'wildcard rule (foo.ck as suffix)'  => [['example', 'foo', 'ck'], 'example', 'foo.ck'],
            'exception rule (www.ck)'           => [['www', 'ck'], 'www', 'ck'],
            'subdomain under exception'         => [['sub', 'www', 'ck'], 'www', 'ck'],
        ];
    }

    /**
     * @dataProvider publicSuffixOnlyProvider
     * @param string[] $labels
     */
    public function testSplitThrowsWhenInputIsExactlyAPublicSuffix(array $labels): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('is a public suffix, not a registrable domain');

        $this->psl->split($labels);
    }

    public static function publicSuffixOnlyProvider(): array
    {
        return [
            'bare gTLD'              => [['com']],
            'listed compound TLD'    => [['co', 'uk']],
            'wildcard-covered label' => [['foo', 'ck']],
        ];
    }
}
