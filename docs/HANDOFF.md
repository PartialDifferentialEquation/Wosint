# Wosint — handoff

Everything you need to pick this up cold. Read the first three sections before
touching anything; the rest is reference.

---

## 1. What this is

Wosint is a **desktop OSINT workbench**. You give it one target — a domain, an
IP, a URL, an email address, a username, a phone number, a person's name, or a
photograph — and it runs a selection of reconnaissance sources against it
concurrently, normalises everything into one searchable table, and correlates
findings across scans into a single profile of the subject.

Three things make it different from a pile of shell scripts:

1. **One interface over two very different worlds.** Local CLI tools
   (`whois`, `sherlock`, `holehe`…) and public web APIs (RDAP, crt.sh,
   CourtListener, Wikidata…) sit behind the same `Module` interface and produce
   the same `Finding` objects, so the rest of the app never cares which it is
   looking at.
2. **Correlation.** Findings are read for the *entity* they were about, merged
   across scans, and scored by independent corroboration. Following a lead adds
   to the picture instead of starting a new one.
3. **It marks its own guesses.** Claims that rest on inference are flagged,
   capped at low confidence, and can never start a chain of further scans. This
   is load-bearing — see §5.

The whole stack is Python, interface included: the GUI is **PySide6 (Qt)**, not
a web app. That was a deliberate choice by the project owner.

---

## 2. Where things stand

| | |
|---|---|
| Branch | `claude/dev-continuation-47l61d`, off `claude/osint-frontend-wrapper-3lpha3` (see §12) |
| Latest commit | `Reopen a saved investigation` |
| Tests | **410 passing**, no network and no CLI tools required |
| Lint | `ruff check` and `ruff format --check` both clean |
| Size | ~7,800 lines of app code, ~4,100 lines of tests |
| Modules | 29 |
| Python | 3.10+ (CI runs 3.10, 3.11, 3.12) |
| PR | None opened yet |

**The nine commits, in order** — each is a coherent milestone and the messages
are detailed:

```
d3057c0  Add Wosint: a PySide6 desktop OSINT workbench
7b7cf1f  Add people targets: usernames, emails, phone numbers and names
e694eda  Correlate findings into a profile, and pivot from one lead to the next
13315e8  Add public-records modules
c0e8949  Add image analysis: offline EXIF and Claude vision
06bbe4c  Rewrite the vision module for the Gemini API
febad6b  Add requirements.txt
23943e7  Add explicit target types, photo intent, and an advanced settings panel
         Reopen a saved investigation
```

### What is proven, and what is not

This matters more than the test count. The suite is hermetic by design, so a
green run says the *parsing and plumbing* are right, not that a remote service
behaves as assumed.

| Verified against the live service | Never called live |
|---|---|
| RDAP, DNS-over-HTTPS, HackerTarget, ip-api, Gravatar, GitLab, SEC EDGAR, CourtListener | **`vision` (Gemini)** — no API key was available |
| | **`wikidata`** — Wikimedia blocks the build sandbox's shared egress IP |
| | **`crtsh`, `wayback`** — blocked by the build sandbox's proxy |
| | **`github`** — the build sandbox's proxy returns 403 on the API |
| | Every `cli` module — none of the tools were installed |
| | `hibp`, `opensanctions`, `opencorporates` — no keys |

That right-hand column was re-checked from a second sandbox and none of it has
moved: Wikimedia answers the shared egress IP with a rate-limit page, crt.sh and
the Wayback CDX endpoint return 502 through the proxy, and the GitHub API still
returns 403. Nothing about that says the modules are wrong — it says these four
have to be verified from an ordinary machine, and nobody has been able to yet.

**The single highest-value first task is to run `vision` against a real Gemini
key.** It is the newest code, it is the only module whose SDK call has never
executed, and `gemini-3.1-pro-preview` was specified by the project owner rather
than confirmed against the models endpoint. If that model id is wrong it is one
constant in `wosint/modules/api_vision.py` (or the `WOSINT_VISION_MODEL`
environment variable) — no code change needed.

CLI modules are lower risk: each parser is tested against captured real-world
output, so the shape is right, but `build_args` has never been executed against
the actual binaries.

---

## 3. Getting it running

```bash
git clone https://github.com/PartialDifferentialEquation/Wosint
cd Wosint
git checkout claude/dev-continuation-47l61d
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

**On headless Linux, Qt needs system libraries** or every import fails with
`ImportError: libEGL.so.1`:

```bash
sudo apt install libegl1 libgl1 libxkbcommon-x11-0 libdbus-1-3 \
                 libfontconfig1 libxcb-cursor0
```

Then:

```bash
wosint                                   # the desktop app
wosint modules                           # catalogue + why anything is unavailable
wosint scan example.com                  # headless, same engine
wosint scan 1.2.3.4 --json               # machine-readable
wosint profile case.json                 # read back a saved profile

QT_QPA_PLATFORM=offscreen pytest         # the suite; offscreen is required
ruff check wosint tests && ruff format --check wosint tests
```

`wosint modules` is the fastest way to see the state of an install — it lists
every module and, for the unavailable ones, exactly what they are waiting on.

### Driving the GUI without a display

Everything below works under `QT_QPA_PLATFORM=offscreen`, which is how the app
was developed and screenshotted:

```python
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from wosint.gui.main_window import MainWindow
from wosint.gui.theme import STYLESHEET
from wosint.core.settings import Settings
import wosint.modules                     # registers the catalogue

app = QApplication([]); app.setStyleSheet(STYLESHEET)
w = MainWindow(Settings()); w.show()
w.target_bar.input.setText("example.com")
w.controller.scan_finished.connect(lambda scan: (w.grab().save("shot.png"), app.quit()))
QTimer.singleShot(200, w.target_bar.scan_button.click)
QTimer.singleShot(30_000, app.quit)       # always have a timeout
app.exec()
```

`w.grab().save(...)` is how the screenshots in `docs/` were produced. Note that
`widget.isVisible()` returns `False` until the parent is actually shown — call
`.show()` before asserting on visibility or you will chase a ghost.

---

## 4. The shape of the code

```
wosint/
  core/          the engine. NEVER imports Qt.
    targets.py     what the user typed → a typed, normalised Target
    models.py      Finding, ModuleResult, Scan, Severity, ModuleStatus
    registry.py    the module catalogue (@register decorator)
    runner.py      ScanRunner: concurrent execution, failure isolation
    process.py     safe subprocess execution (never a shell)
    http.py        shared httpx client + HttpError carrying a status code
    settings.py    config file + environment overrides + API keys
    entities.py    Entity/Relation/Source — what a finding was *about*
    correlate.py   Investigation: merging, linking, confidence, pivots
  modules/       one file per source, all behind base.py's Module interface
  gui/           the ONLY package that imports Qt
    controller.py  asyncio-in-a-thread bridge → Qt signals
    main_window.py, settings_dialog.py, theme.py, models.py
    widgets/       target_bar, module_panel, results_panel, profile_panel
  cli.py         headless interface over the same engine
  __main__.py    entry point: GUI by default, `scan` / `modules` subcommands
```

The layering is the point. `core` is a plain asyncio library with three
independent consumers — the GUI, the CLI, and the tests. If you find yourself
needing Qt in `core`, or business logic in a widget, something has gone wrong.

### How a scan actually flows

```
TargetBar          → parse_target()/coerce_target() → Target
MainWindow         → ScanController.submit(target, module_names)
ScanController     → asyncio.run_coroutine_threadsafe onto its own thread
ScanRunner.run()   → modules_for(target) → asyncio.gather, capped by a semaphore
  each module      → Module.execute() → ModuleOutput(findings, raw)
  on_update        → Qt signal (a deepcopy) → queued onto the GUI thread
ResultsPanel       → tables update live
ProfilePanel       → Investigation.add_scan(scan) → merged entities + pivots
```

The GUI runs the engine on a **background thread with its own event loop** and
receives progress as Qt signals. Qt delivers those as queued calls on the GUI
thread, so no widget is ever touched from the worker and a slow module cannot
freeze the window.

---

## 5. Invariants — do not break these

These are the rules the codebase relies on. Most were learned by breaking them.

1. **`wosint/core` never imports Qt.** Three consumers depend on it.
2. **A module failing never stops a scan.** Modules raise on genuine failure;
   `ScanRunner._run_one` converts *every* exception into a `ModuleStatus` on
   that module's row. Do not add a `try/except` in the runner's caller.
3. **Subprocesses take an argument list, never a shell string.** `process.py`
   uses `create_subprocess_exec` with `start_new_session=True` and kills by
   process group on timeout. Targets are validated by `targets.py` before they
   can reach it. A target like `example.com; rm -rf ~` is one inert argument —
   there is a test asserting exactly that.
4. **Anything resting on a guess sets `inferred=True`.** This is the safety
   mechanism that stops the tool merging two different people:
   - inferred entities are capped at confidence `0.25` however many modules
     repeat them (repeating a guess is not corroboration),
   - they render greyed and italic as "inferred, unconfirmed",
   - **they are never offered as pivots** — chaining a scan off a guess is
     precisely how a stranger's data ends up in someone's profile,
   - one *confirmed* source promotes them to real.

   If you add a module that guesses an identifier (e.g. trying an email local
   part as a handle), mark every finding it produces.
5. **A non-404 HTTP error is not "not found".** `HttpError.status_code` exists
   for this. Treating a 403 or a rate limit as "no such account" silently
   reports a clean miss — see §9.
6. **Links we construct are not evidence.** Search URLs and record links we
   built ourselves are excluded from entity extraction (`SKIP_LABELS` and the
   `search` category in `correlate.py`). They are places to look, not findings.
7. **Emit copies across the thread boundary.** `ScanController._on_update`
   deepcopies the `ModuleResult` before emitting, because the engine keeps
   mutating the original on the worker thread.
8. **Environment-provided API keys are never written to disk.** `Settings`
   tracks `env_keys` and excludes them from `save()`; the config file is
   written `0600`.
9. **`ScanController.is_scanning` is an explicit flag**, not derived from the
   future's done-state. See §9.

---

## 6. Adding a module

This is the main extension point and it is deliberately small. Pick a base
class by what the module *does*:

| Base | `kind` | Use when | Availability gate |
|---|---|---|---|
| `ApiModule` | `api` | queries an HTTP endpoint | `requires_key = True` → needs `WOSINT_KEY_<NAME>` |
| `CliModule` | `cli` | shells out to a local tool | `tool` must be on `PATH` |
| `LocalModule` | `local` | pure computation, sends nothing | always available |

```python
import json

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext


@register
class MySourceModule(ApiModule):
    """One line on what this finds."""

    name = "mysource"                      # unique; duplicates raise at import
    title = "My source"                    # shown in the UI
    description = "What it finds, in a sentence."
    source_url = "https://example.com"     # shown so analysts see what is queried
    supported_types = frozenset({TargetType.DOMAIN})
    default_enabled = True                 # False for slow/noisy sources

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        data = await get_json(ctx.client, f"https://example.com/api/{target.value}")
        out.add("dns", "Host", data["host"], "detail line", Severity.NOTABLE)
        out.raw = json.dumps(data, indent=2)   # always keep the untouched output
        return out
```

Then add it to the import list in `wosint/modules/__init__.py` — that import is
what registers it — and it appears in the GUI, the CLI and `wosint modules`
automatically. Nothing else needs changing.

`CliModule` is even smaller: implement `build_args(target, ctx)` and
`parse(output, target)`; the base class runs the tool, applies the timeout, and
raises if it exits non-zero with no findings.

**Conventions worth following:**

- `out.add()` ignores blank values, so you can call it unconditionally.
- Categories in use: `account`, `archive`, `breach`, `certificate`, `contact`,
  `dns`, `image`, `meta`, `network`, `phone`, `profile`, `records`,
  `registration`, `search`. Reuse one; the correlator routes on category and
  label.
- Severity means **notability, not vulnerability**. `WARNING` is for something
  an analyst should look at now (a domain accepting mail with no SPF; a photo
  carrying GPS), not for "a vulnerability".
- Cap large result sets and say you did — see `MAX_HOSTED_DOMAINS` in
  `api_hackertarget.py`, which stops a shared IP burying every other finding.

---

## 7. The correlation engine

`entities.py` + `correlate.py`. This is the least obvious part of the codebase.

- **`Entity`** — a normalised thing (name, email, username, phone, account,
  organisation, location, domain, URL, IP, breach, document) plus every
  `Source` that attested to it. `normalise()` is where correlation is really
  decided: two values that normalise identically become one entity.
- **`Investigation`** — accumulates scans. `add_scan()` extracts entities,
  merges them, and links each to the scan's subject with a stated reason.
- **Confidence** counts *independent modules*, not repeated claims, and adds a
  bonus for being seen from more than one starting target. All-inferred
  entities are pinned at `0.25`.
- **Pivots** — identifiers worth scanning next. `PIVOTABLE` maps entity types to
  target types; the parsed type must agree with the expected one, so a one-word
  name cannot silently become a username pivot.
- **`handle_from_url()`** is what turns "an account exists" into a scannable
  lead: it recognises ~11 profile URL shapes and extracts the handle. It returns
  `None` for shapes it does not know rather than guessing at a path segment.

The payoff chain, which works end to end against live services:

```
bob@example.com → Gravatar → linked GitHub account
                → handle "bobsmith" → rescan → employer, location, more accounts
```

`ProfilePanel` renders this; double-clicking a lead in "Follow next" scans it
into the same profile.

An investigation round-trips through JSON: `as_dict()` writes it,
`Investigation.from_dict()` / `from_json()` read it back, and `merge()` folds one
into another so a reopened profile keeps growing. Only *stated* facts are read —
sources, edges, what has been scanned. Confidence, `is_inferred` and the pivots
are recomputed from the sources on the way in, deliberately: the file is on disk
between sessions and an edited one must not be able to assert a confidence, or
offer a lead, that its provenance does not support. Anything unusable is refused
with `InvestigationError` rather than half-loaded, and an entity with no sources
is refused outright — nothing in a profile is unattributable.

The GUI reaches this through **File → Open saved profile…** (`Ctrl+Shift+O`),
which asks whether to merge or replace when a profile is already open;
`wosint profile <file>` prints one headlessly. `FORMAT_VERSION` in
`correlate.py` guards the format: a file with no version is read as version 1,
and a newer one is refused rather than misread.

---

## 8. Settings and keys

Config lives at `~/.config/wosint/config.json` (override with `WOSINT_CONFIG`).
**Settings → Advanced settings…** (`Ctrl+,`) edits it: API keys, timeouts,
concurrency, user agent, contact address, phone region, and a per-module on/off
switch.

Every scalar has an environment override, which wins over the file:

| Variable | Effect |
|---|---|
| `WOSINT_CONFIG` | Use a different config file |
| `WOSINT_MODULE_TIMEOUT` | Seconds before a module is killed |
| `WOSINT_MAX_CONCURRENCY` | How many modules run at once |
| `WOSINT_HTTP_TIMEOUT` | Per-request timeout |
| `WOSINT_USER_AGENT` | Sent with every outbound request |
| `WOSINT_PHONE_REGION` | Region for numbers typed without a country code |
| `WOSINT_CONTACT_EMAIL` | Contact address — the SEC refuses requests without it |
| `WOSINT_VISION_MODEL` | Overrides the Gemini model id |
| `WOSINT_DISABLED_MODULES` | Comma-separated modules to hide entirely |
| `WOSINT_KEY_<MODULE>` | API key, e.g. `WOSINT_KEY_HIBP` |

Modules needing a key: `vision`, `hibp`, `opensanctions`, `opencorporates`.
`courtlistener` takes an optional token that only raises its rate limit.
`vision` also accepts the SDK's own `GEMINI_API_KEY` / `GOOGLE_API_KEY`.

A malformed config file is ignored rather than fatal — failing to start over a
stray comma would be worse than using defaults.

---

## 9. Traps found the hard way

Every one of these was a real bug caught by running the thing. They will bite
again if the reasoning is lost.

**Correlation**

- **An email's local part is not a handle.** Scanning `beau@…` guessed `beau` as
  a GitHub/GitLab handle and pulled a *different real person's* name into the
  profile. This is why `inferred` exists (§5.4).
- **GitLab's `/users?username=` is a search, not a lookup.** Its first result
  need not be the handle you asked for. Match exactly. Assume the same of any
  "search" endpoint.

**Qt**

- **`invalidateFilter()` / `invalidateRowsFilter()` are deprecated** in Qt 6.
  Use `invalidate()`. This mattered more than it sounds: the call was inside a
  signal handler, and **a Python exception raised inside a Qt slot is printed
  and swallowed, not propagated** — so filtering silently stopped working. If a
  slot "does nothing", check stderr.
- **`ScanController.is_scanning` cannot read the future.** Terminal signals are
  emitted from *inside* the coroutine, so the future is still not-done while a
  `scan_finished` handler runs. Anything gated on it gets refused at exactly the
  moment the user acts on a result. Hence the explicit `_active` flag.
- **Qt's content-based column sizing ignores stylesheet cell padding**, so text
  elides by a pixel or two. `results_panel._fit_columns` adds `COLUMN_PADDING`.
- **Mutable class attributes are shared between instances.** `ResultsPanel`'s
  raw-output cache was briefly a class attribute; it must be per-instance.

**Protocols**

- **PTR lookups need the `in-addr.arpa` name**, not the raw IP. Querying the
  literal silently returns nothing.
- **Several httpx transport errors stringify to `""`**, leaving a blank reason
  in the UI. `http.py` falls back to the exception class name.

**Testing**

- `pyproject.toml` sets `filterwarnings = ["error::DeprecationWarning:wosint.*"]`.
  That is what caught the Qt deprecation. Keep it.
- `asyncio_mode = "auto"` is set, so `async def test_…` needs no decorator.

---

## 10. Testing conventions

The suite must keep running with **no network and none of the CLI tools
installed**. That is what makes it usable in CI and on any machine.

| Kind of module | How it is tested |
|---|---|
| `api` | `respx` mocks the HTTP response |
| `cli` | captured real tool output fed straight to `parse()`; `build_args` asserted separately |
| `local` | called directly |
| `vision` | a stubbed SDK client (`FakeClient`) recording the request |
| GUI | `QT_QPA_PLATFORM=offscreen`, widgets driven directly |

Fixtures live in `tests/conftest.py`: `ctx` (a `RunContext` with a real client
for respx to intercept), `settings`, and `isolated_registry` — use the last one
whenever a test registers its own modules, or it will leak into the real
catalogue.

Test names are sentences describing the behaviour, and several carry a
docstring explaining *why the rule exists* rather than what the code does. That
is deliberate: it is where the reasoning above is recorded.

---

## 11. The boundary on face recognition

The project owner asked for "llm to process photos to connect people". What was
built reads images for **identifiers that can be looked up** — text, handles on
screens, signage, employer logos, landmarks. What was deliberately **not** built
is face matching: identifying a person, or linking two photos as the same
person, from their face.

That is not an oversight or an unfinished feature. Biometric identification of
individuals is unlawful without consent in a good part of the world (GDPR Art. 9,
Illinois BIPA, the EU AI Act's ban on untargeted facial-image scraping), and
wiring it into a people-search tool is the Clearview AI pattern. The model is
instructed not to identify anyone by face and not to guess protected
characteristics, and the people-focused prompt repeats that rather than relying
on the system prompt alone.

**If you are asked to add it, treat it as a decision to escalate, not a ticket.**
The rest of the tool is defensible; that one capability changes what it is.

The same instinct runs through the correlation design: individually harmless
facts become a profile once joined up, and assembly is the step regulators treat
as processing. Hence provenance on every entity, guesses marked and never
chained, and the advice in the README to delete an investigation when it is done.

---

## 12. Suggested next steps

Roughly in order of value:

1. **Run `vision` against a real Gemini key.** The only completely unexercised
   code path, and it will confirm or refute the `gemini-3.1-pro-preview` model
   id in one call.
2. **Verify `wikidata`, `crtsh`, `wayback` and `github` from a normal IP.** All
   four were blocked by the build sandbox, not by bugs — but "should work" is
   not "works".
3. **A relationship view.** `Relation` edges are built and carry reasons, but
   are only surfaced in tooltips. A graph would show the shape of a profile.
4. **Response caching / rate limiting** for API modules. Several sources are
   rate limited and re-scanning repeats identical requests.
5. **Package a real binary** (PyInstaller) so it installs like a desktop app.
6. **More sources.** The module interface is the cheap part — each new one is
   one file plus one import line.
7. **Auto-save the open investigation** now that it round-trips, so closing the
   window does not lose an afternoon's work. The pieces are all there; what
   needs deciding is where it lives and when it is deleted, which is a privacy
   question as much as a storage one (see §11).

Two smaller things worth knowing. The repository was created completely empty —
there is still **no `main` branch on the remote at all**, only
`claude/osint-frontend-wrapper-3lpha3` and `claude/dev-continuation-47l61d`
(which contains it), so whoever opens the first PR will need to create a default
branch or merge one of these into a new `main`. And no PR has been opened yet.

---

## 13. Where to look first

| I want to… | Read |
|---|---|
| Understand a target being misread | `wosint/core/targets.py` |
| Add or debug a source | `wosint/modules/base.py`, then any sibling |
| Understand why a scan reported a status | `wosint/core/runner.py` |
| Understand the profile / confidence | `wosint/core/correlate.py` |
| Change what the UI does | `wosint/gui/main_window.py` and `widgets/` |
| Know why a decision was made | the commit messages — they are detailed |
