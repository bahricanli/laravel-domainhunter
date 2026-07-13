# laravel-domainhunter

Framework-agnostic WHOIS lookup and domain-name parsing library, extracted
from [domainhunter](https://github.com/bmericc/domainhunter) so the same
logic can be shared between:

- **domainhunter** (Slim 4) — the original CLI/web domain-watch tool
- **domainhunter-app** (Laravel) — the multi-user, registrar-API/MCP-enabled rewrite

## What it does

- `BahriCanli\DomainHunter\WhoisService` — performs WHOIS/RDAP lookups
- `BahriCanli\DomainHunter\WhoisResult` — value object for parsed WHOIS data
- `BahriCanli\DomainHunter\DomainParser` — compound-TLD detection, Punycode/IDN
  conversion and label validation

No framework dependencies — only `ext-intl` is required.

## Installation

```bash
composer require bahricanli/domainhunter
```

## License

GPL-3.0-or-later, consistent with the domainhunter project it was extracted from.
