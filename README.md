# Wosint

A desktop OSINT workbench. Wosint puts local reconnaissance tools and public
web APIs behind one Qt interface: type a target, pick your modules, and get
every result normalised into a single searchable table.

Everything is written in Python, including the interface — the frontend is
PySide6 (Qt), not a web app.

![Wosint findings view](docs/screenshot-findings.png)

Scanning a phone number, with the two offline modules selected and the sidebar
noting that the target is a person:

![Wosint scanning a phone number](docs/screenshot-phone.png)

## Why

Reconnaissance normally means running half a dozen tools by hand and reading
half a dozen different output formats. Wosint runs them concurrently against
one target and folds the results into a common shape, while keeping every
tool's raw output one click away.

It handles both halves of a normal investigation: infrastructure (domains, IP
addresses, URLs) and people (email addresses, usernames, phone numbers, names).

Modules come in three kinds and the interface treats them identically:

- **API modules** query public endpoints over HTTPS. They need nothing
  installed and work out of the box.
- **CLI modules** shell out to tools you already have. When a tool is missing
  the module is shown greyed out with an install hint rather than failing
  mid-scan.
- **Local modules** work the target out on this machine and send nothing
  anywhere. The interface labels them, so when the target is a person you can
  see at a glance which modules disclose them to a third party and which do not.

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
wosint scan bob@example.com                # email: provider, profiles, accounts
wosint scan "+1 415 555 0100" -m phone     # offline number analysis
wosint scan "Ada Lovelace"                 # person: search starting points
wosint modules                             # catalogue and availability
```

### Targets

Wosint works out what you gave it, and modules declare which kinds they
understand — there is no point offering a username lookup for an IP address, so
it is not shown.

| You type | Read as |
| --- | --- |
| `example.com`, `a.example.co.uk` | Domain |
| `1.2.3.4`, `2001:db8::1` | IP address |
| `https://example.com/path` | URL |
| `bob@example.com` | Email address |
| `some_user` | Username |
| `+1 415 555 0100`, `(415) 555-0100`, `00 44 20 7183 8750` | Phone number |
| `Ada Lovelace`, `Renée O'Brien` | Person |

Classification is deliberately conservative where two readings are possible. A
dotted number like `415.555.0100` is a phone number rather than a domain, since
no real TLD is numeric; `user.name-1` is a username for the same reason. A
single word is read as a username rather than a name, because a handle is the
more useful reading. Whatever it decides, the badge beside the input shows it
before you press Enter.

A phone number typed without a country code is genuinely ambiguous. Wosint says
so rather than guessing — set `WOSINT_PHONE_REGION` (for example `GB`) to have
such numbers interpreted for that country.

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

Person-oriented modules:

| Module | Kind | Targets | What it finds |
| --- | --- | --- | --- |
| `email` | local | email | Role vs. individual mailbox, provider class, sub-address tags, probable name |
| `phone` | local | phone | Country, region, carrier, line type, timezone and dialling formats |
| `links` | local | person, username, email, phone | Ready-made search queries and candidate profile URLs |
| `gravatar` | api | email | Public profile, avatar, and the accounts linked from it |
| `github` | api | username, email | Name, employer, location and published email on a GitHub profile |
| `gitlab` | api | username, email | GitLab profile for a handle |
| `hibp` | api | email | Breaches containing an address (needs an API key) |
| `holehe` | cli | email | Sites where an address is already registered |
| `maigret` | cli | username, email | Wide username search that also extracts profile details |
| `phoneinfoga` | cli | phone | Online scanner results for a number |

The three `local` modules never touch the network. `email`, `phone` and `links`
therefore work offline, and give you something to go on before deciding whether
to make any outbound query at all.

CLI modules are optional. Install only the ones you want:

```bash
sudo apt install whois dnsutils
pipx install sherlock-project theHarvester holehe maigret
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# phoneinfoga: https://sundowndev.github.io/phoneinfoga/install/
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
| `WOSINT_PHONE_REGION` | Two-letter region for numbers typed without a country code |
| `WOSINT_KEY_<MODULE>` | API key for a module that needs one, e.g. `WOSINT_KEY_HIBP` |

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

Searching for a person raises a second question on top of that one. An email
address, a username, a phone number and a name are personal data, and in most
jurisdictions collecting them needs a lawful basis regardless of how public each
individual fact is; assembling scattered public details into one profile is
exactly the step that regulators treat as processing. Wosint therefore says so
in the sidebar whenever the target is a person, and tells you which of the
selected modules would disclose that person to a third party just by asking
about them. Have a reason, keep the results no longer than you need them, and do
not use this to build a profile of someone who has not consented and whom you
have no authorisation to investigate.
