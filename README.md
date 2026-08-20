# Wosint

A desktop OSINT workbench. Wosint puts local reconnaissance tools and public
web APIs behind one Qt interface: type a target, pick your modules, and get
every result normalised into a single searchable table.

Everything is written in Python, including the interface — the frontend is
PySide6 (Qt), not a web app.

![Wosint findings view](docs/screenshot-findings.png)

## Why

Reconnaissance normally means running half a dozen tools by hand and reading
half a dozen different output formats. Wosint runs them concurrently against
one target and folds the results into a common shape, while keeping every
tool's raw output one click away.

Modules come in two kinds and the interface treats them identically:

- **API modules** query public endpoints over HTTPS. They need nothing
  installed and work out of the box.
- **CLI modules** shell out to tools you already have. When a tool is missing
  the module is shown greyed out with an install hint rather than failing
  mid-scan.

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/PartialDifferentialEquation/Wosint
cd Wosint
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

On a headless Linux box, Qt also needs its system libraries:

```bash
sudo apt install libegl1 libgl1 libxkbcommon-x11-0 libdbus-1-3 libfontconfig1 libxcb-cursor0
```

## Use

Open the desktop application:

```bash
wosint              # or: python -m wosint
```

Type a target and press Enter. Wosint classifies the input as you type — the
badge next to the box shows whether `bob@example.com` was read as an email
address or something else — and the sidebar narrows to the modules that apply.

The same engine runs from a terminal, which is useful for scripting and on
machines without a display:

```bash
wosint scan example.com                    # every applicable module
wosint scan example.com -m dns -m rdap     # just these two
wosint scan 1.2.3.4 --json > scan.json     # machine-readable
wosint modules                             # catalogue and availability
```

### Targets

Wosint works out what you gave it. Domains, IPv4 and IPv6 addresses, URLs,
email addresses and usernames are all recognised, and modules declare which
kinds they understand — there is no point offering a username lookup for an IP
address, so it is not shown.

### Modules

| Module | Kind | Targets | What it finds |
| --- | --- | --- | --- |
| `rdap` | api | domain, ip, url, email | Registrar, registration dates, nameservers, status flags |
| `dns` | api | domain, ip, url, email | A/AAAA/MX/NS/TXT/SOA over DNS-over-HTTPS, PTR for addresses |
| `crtsh` | api | domain, url, email | Subdomains and issuers from Certificate Transparency logs |
| `hackertarget` | api | domain, ipv4, url, email | Passive host search and reverse-IP lookups |
| `geoip` | api | ipv4, ipv6 | Location, ISP, ASN, hosting and proxy classification |
| `wayback` | api | domain, url, email | Historical URLs from the Internet Archive |
| `whois` | cli | domain, ip, url, email | Registration record from the local `whois` client |
| `dig` | cli | domain, ip, url, email | Records as seen by *this* machine's resolver |
| `subfinder` | cli | domain, url, email | Passive subdomain enumeration across aggregated sources |
| `theharvester` | cli | domain, url, email | Emails and hostnames from search engines and datasets |
| `sherlock` | cli | username, email | Accounts matching a username across social platforms |

CLI modules are optional. Install only the ones you want:

```bash
sudo apt install whois dnsutils
pipx install sherlock-project theHarvester
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Reading results

Findings carry a severity that reflects **notability, not vulnerability** —
Wosint reports what is publicly observable and leaves the judgement to you. A
domain that publishes MX records but no SPF policy is flagged as a warning
because it is spoofable; a `staging.` subdomain in a certificate log is marked
notable because it is worth a look.

The **Findings** tab is filterable by text and by severity. **Modules** shows
what ran, how long it took and why anything failed. **Raw output** keeps each
tool's untouched output, so nothing is hidden behind the parser. Double-click
any cell to copy it. `Ctrl+S` exports the whole scan as JSON; the Export menu
also writes the visible findings to CSV.

## Configuration

Settings live in `~/.config/wosint/config.json` and every value can be
overridden by an environment variable:

```json
{
  "module_timeout": 45.0,
  "max_concurrency": 6,
  "http_timeout": 20.0,
  "disabled_modules": []
}
```

| Variable | Effect |
| --- | --- |
| `WOSINT_CONFIG` | Use a different config file |
| `WOSINT_MODULE_TIMEOUT` | Seconds before a module is killed |
| `WOSINT_MAX_CONCURRENCY` | How many modules run at once |
| `WOSINT_HTTP_TIMEOUT` | Per-request timeout for API modules |
| `WOSINT_DISABLED_MODULES` | Comma-separated modules to hide entirely |
| `WOSINT_KEY_<MODULE>` | API key for a module that needs one |

A malformed config file is ignored rather than fatal — Wosint starts with
defaults instead of refusing to open over a stray comma.

## How it fits together

```
wosint/
  core/         the engine: targets, models, registry, runner, subprocess and HTTP helpers
  modules/      one file per source, all behind the same Module interface
  gui/          the only package that imports Qt
  cli.py        headless interface over the same engine
```

The engine is plain asyncio and knows nothing about Qt. The GUI runs it on a
background thread with its own event loop and receives progress as Qt signals,
which Qt delivers as queued calls on the GUI thread — so no widget is ever
touched from the worker, and a slow module never freezes the window.

One module failing never affects another: every error, timeout and missing tool
becomes a status on that module's row, and the scan carries on.

### Adding a module

Subclass `ApiModule` or `CliModule`, declare what it supports, and register it:

```python
@register
class MyModule(ApiModule):
    name = "mysource"
    title = "My source"
    supported_types = frozenset({TargetType.DOMAIN})

    async def execute(self, target, ctx):
        out = ModuleOutput()
        data = await get_json(ctx.client, f"https://example.com/api/{target.value}")
        out.add("dns", "Host", data["host"])
        return out
```

Add it to the import list in `wosint/modules/__init__.py` and it appears in
both the GUI and the CLI. Nothing else needs to change.

## Development

```bash
QT_QPA_PLATFORM=offscreen pytest
```

The suite runs without network access and without any of the CLI tools
installed: API modules are tested against mocked HTTP responses, CLI modules
are tested by feeding captured output to their parsers, and the GUI tests run
against Qt's offscreen platform.

## Authorised use only

Wosint gathers information from public sources, but "passive" is not the same
as "permitted". Only run it against infrastructure you own or have written
authorisation to assess. Some modules query third-party services — the module
list shows which — and those services have their own terms and rate limits.
