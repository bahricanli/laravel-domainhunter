<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter;

/**
 * Framework-agnostic domain-name parsing: public-suffix-aware TLD detection,
 * Punycode/IDN conversion and label validation.
 *
 * Extracted from domainhunter's App\Service\DomainService so the same
 * parsing rules can be shared by domainhunter (Slim) and domanhunter-app
 * (Laravel) without duplicating logic.
 */
class DomainParser
{
    private readonly PublicSuffixList $publicSuffixList;

    // $whois is unused here - kept for constructor backward compatibility
    // with existing call sites in domainhunter/domainhunter-app.
    public function __construct(
        private readonly WhoisService $whois,
        ?PublicSuffixList $publicSuffixList = null,
    ) {
        $this->publicSuffixList = $publicSuffixList ?? new PublicSuffixList();
    }

    /**
     * @return array{label: string, tld: string}
     */
    public function parse(string $input): array
    {
        $input = strtolower(trim($input));
        $input = preg_replace('/^www\./', '', $input) ?? $input;
        $parts = explode('.', $input);

        if (count($parts) < 2) {
            throw new \InvalidArgumentException("Invalid domain format. Example: example.com or example.com.tr");
        }

        // Resolve the registrable label/TLD split against the real Public
        // Suffix List rather than guessing from a short hand-curated list of
        // known compound TLDs - that guesswork silently mis-splits any
        // registry suffix that isn't on the list (e.g. "example.com.br":
        // "br" alone is a known TLD, so a naive guess treats "com" as the
        // label and "br" as the TLD instead of recognizing "com.br" as the
        // suffix). Any labels further left than the resolved suffix are a
        // subdomain prefix and are intentionally discarded, however deeply
        // nested (e.g. "blog"/"a.b.c" in "blog.example.com" /
        // "a.b.c.example.com") - only the registrable domain (the thing
        // WHOIS/RDAP actually indexes) is returned.
        ['label' => $label, 'tld' => $tld] = $this->publicSuffixList->split($parts);

        return $this->validateLabel($this->toPunycode($label), $tld);
    }

    /**
     * Converts a Unicode label to its ASCII-compatible encoding (Punycode).
     * Passes ASCII labels through unchanged.
     */
    public function toPunycode(string $label): string
    {
        if (!function_exists('idn_to_ascii') || mb_detect_encoding($label, 'ASCII', true) !== false) {
            return $label;
        }

        $ascii = idn_to_ascii($label, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($ascii === false) {
            throw new \InvalidArgumentException("Cannot convert \"$label\" to ASCII/Punycode.");
        }

        return $ascii;
    }

    /**
     * @return array{label: string, tld: string}
     */
    private function validateLabel(string $label, string $tld): array
    {
        if (strlen($label) < 2) {
            throw new \InvalidArgumentException("Domain label is too short.");
        }
        if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$/', $label)) {
            throw new \InvalidArgumentException("Domain label contains invalid characters.");
        }
        return ['label' => $label, 'tld' => $tld];
    }
}
