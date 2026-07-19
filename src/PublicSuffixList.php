<?php

declare(strict_types=1);

namespace BahriCanli\DomainHunter;

/**
 * ICANN section of the Mozilla Public Suffix List (https://publicsuffix.org),
 * used to correctly split a hostname into its registrable label and the
 * (possibly multi-label) suffix actually assigned by a registry - e.g.
 * "co.uk", "com.br", "com.tr" - instead of guessing from a short hand-curated
 * list of known compound TLDs, which silently mis-splits any registry suffix
 * that isn't on that list (see e.g. "example.com.br": "br" alone is a known
 * TLD, so a hand-curated guess treats "com" as the registrable label and
 * "br" as the TLD, instead of recognizing "com.br" as the suffix).
 */
final class PublicSuffixList
{
    /** @var array<string, array{0: array<string, true>, 1: array<string, true>}> */
    private static array $cache = [];

    public function __construct(
        private readonly string $path = __DIR__ . '/../resources/public_suffix_list.dat',
    ) {
    }

    /**
     * Splits already-lowercased, dot-separated labels into the immediate
     * registrable label and its public suffix, discarding any further
     * subdomain labels to the left.
     *
     * @param string[] $labels
     * @return array{label: string, tld: string}
     */
    public function split(array $labels): array
    {
        $n = count($labels);
        $suffixLabelCount = $this->publicSuffixLabelCount($labels);

        if ($n <= $suffixLabelCount) {
            throw new \InvalidArgumentException(
                '"' . implode('.', $labels) . '" is a public suffix, not a registrable domain.'
            );
        }

        return [
            'label' => $labels[$n - $suffixLabelCount - 1],
            'tld'   => implode('.', array_slice($labels, $n - $suffixLabelCount)),
        ];
    }

    /**
     * @param string[] $labels
     */
    private function publicSuffixLabelCount(array $labels): int
    {
        [$rules, $exceptions] = $this->rules();
        $n = count($labels);

        $exceptionTake = null;
        $ruleTake = null;

        for ($take = 1; $take <= $n; $take++) {
            $suffixLabels = array_slice($labels, $n - $take);
            $candidate    = implode('.', $suffixLabels);

            if (isset($exceptions[$candidate])) {
                $exceptionTake = $take;
            }

            if (isset($rules[$candidate])) {
                $ruleTake = $take;
            } else {
                $wildcard    = $suffixLabels;
                $wildcard[0] = '*';
                if (isset($rules[implode('.', $wildcard)])) {
                    $ruleTake = $take;
                }
            }
        }

        // A matching exception rule always overrides a matching (possibly
        // longer) ordinary rule - see the "Algorithm" section of
        // https://publicsuffix.org/list/. Per the exception, the labels it
        // names are themselves registrable, so the suffix is one label
        // shorter than the exception match.
        if ($exceptionTake !== null) {
            return $exceptionTake - 1;
        }

        // No rule matched at all: the default rule is "*", i.e. the last
        // label alone is the suffix.
        return $ruleTake ?? 1;
    }

    /**
     * @return array{0: array<string, true>, 1: array<string, true>}
     */
    private function rules(): array
    {
        if (!isset(self::$cache[$this->path])) {
            self::$cache[$this->path] = $this->load();
        }

        return self::$cache[$this->path];
    }

    /**
     * @return array{0: array<string, true>, 1: array<string, true>}
     */
    private function load(): array
    {
        $lines = file($this->path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            throw new \RuntimeException("Could not read public suffix list at \"{$this->path}\".");
        }

        $rules      = [];
        $exceptions = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '//')) {
                continue;
            }

            if ($line[0] === '!') {
                $exceptions[strtolower(substr($line, 1))] = true;
            } else {
                $rules[strtolower($line)] = true;
            }
        }

        return [$rules, $exceptions];
    }
}
