<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter;

/**
 * Framework-agnostic domain-name parsing: compound-TLD detection,
 * Punycode/IDN conversion and label validation.
 *
 * Extracted from domainhunter's App\Service\DomainService so the same
 * parsing rules can be shared by domainhunter (Slim) and domanhunter-app
 * (Laravel) without duplicating logic.
 */
class DomainParser
{
    public function __construct(private readonly WhoisService $whois)
    {
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

        // Detect compound TLDs (e.g. com.tr, co.uk, com.au) before single-part fallback
        if (count($parts) >= 3) {
            $candidate = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
            if (in_array($candidate, $this->whois->compoundTlds(), true)) {
                $label = $this->toPunycode(implode('.', array_slice($parts, 0, -2)));
                return $this->validateLabel($label, $candidate);
            }
        }

        $tld   = array_pop($parts);
        $label = $this->toPunycode(implode('.', $parts));

        return $this->validateLabel($label, $tld);
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
