"""CLI module argument construction and output parsing.

These tests never invoke the real tools: they feed captured output straight to
each module's parser, so the suite runs identically on a machine with none of
the tooling installed.
"""

from __future__ import annotations

import pytest

from wosint.core.models import Severity
from wosint.core.process import CommandOutput
from wosint.core.registry import get_module
from wosint.core.settings import Settings
from wosint.core.targets import parse_target


def out(stdout: str, returncode: int = 0) -> CommandOutput:
    return CommandOutput(returncode=returncode, stdout=stdout, stderr="")


def values(result, label: str) -> list[str]:
    return [f.value for f in result.findings if f.label == label]


# -- argument construction ---------------------------------------------------


@pytest.mark.parametrize(
    ("module", "target", "expected_tail"),
    [
        ("whois", "example.com", ["--", "example.com"]),
        ("whois", "bob@example.com", ["--", "example.com"]),
        ("whois", "1.2.3.4", ["--", "1.2.3.4"]),
        ("subfinder", "example.com", ["-d", "example.com"]),
        ("sherlock", "some_user", ["--", "some_user"]),
        ("sherlock", "bob@example.com", ["--", "bob"]),
    ],
)
def test_build_args_tail(module: str, target: str, expected_tail: list[str], ctx) -> None:
    args = get_module(module).build_args(parse_target(target), ctx)
    assert args[-len(expected_tail) :] == expected_tail


def test_build_args_never_uses_a_shell_string(ctx) -> None:
    """Every argument list must stay a list, one token per element."""
    for name in ("whois", "dig", "subfinder", "sherlock", "theharvester"):
        module = get_module(name)
        target = parse_target("some_user" if name == "sherlock" else "example.com")
        args = module.build_args(target, ctx)
        assert isinstance(args, list)
        assert all(isinstance(a, str) for a in args)
        assert args[0] == module.tool


def test_dig_requests_every_record_type(ctx) -> None:
    args = get_module("dig").build_args(parse_target("example.com"), ctx)
    assert args.count("example.com") == 7
    assert "MX" in args and "SOA" in args


def test_dig_uses_reverse_lookup_for_ips(ctx) -> None:
    args = get_module("dig").build_args(parse_target("1.2.3.4"), ctx)
    assert args[-2:] == ["-x", "1.2.3.4"]


# -- whois -------------------------------------------------------------------

WHOIS_OUTPUT = """\
% This is a comment that should be ignored
Domain Name: EXAMPLE.COM
Registrar: Acme Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp
Domain Status: clientHold https://icann.org/epp
Name Server: NS1.EXAMPLE.COM
Name Server: NS1.EXAMPLE.COM
Registrant Organization: REDACTED FOR PRIVACY
NotAKnownField: ignored
"""


def test_whois_extracts_known_fields() -> None:
    result = get_module("whois").parse(out(WHOIS_OUTPUT), parse_target("example.com"))

    assert values(result, "Registrar") == ["Acme Registrar, Inc."]
    assert values(result, "Created") == ["1995-08-14T04:00:00Z"]
    assert values(result, "Expires") == ["2027-08-13T04:00:00Z"]
    # Repeated identical values collapse to one finding.
    assert values(result, "Nameserver") == ["NS1.EXAMPLE.COM"]


def test_whois_flags_hold_status_and_privacy() -> None:
    result = get_module("whois").parse(out(WHOIS_OUTPUT), parse_target("example.com"))

    statuses = {f.value: f.severity for f in result.findings if f.label == "Status"}
    assert statuses["clientHold https://icann.org/epp"] is Severity.WARNING
    assert statuses["clientTransferProhibited https://icann.org/epp"] is Severity.INFO
    assert values(result, "Privacy") == ["registrant details are redacted"]


def test_whois_ignores_comments_and_unknown_keys() -> None:
    result = get_module("whois").parse(out(WHOIS_OUTPUT), parse_target("example.com"))
    assert "ignored" not in [f.value for f in result.findings]


# -- dig ---------------------------------------------------------------------

DIG_OUTPUT = """\
; <<>> DiG 9.18 <<>> example.com A
example.com.		300	IN	A	93.184.216.34
example.com.		300	IN	A	93.184.216.34
example.com.		3600	IN	MX	10 mail.example.com.
example.com.		3600	IN	TXT	"v=spf1 -all"
4.3.2.1.in-addr.arpa.	600	IN	PTR	host.example.com.
"""


def test_dig_parses_answer_lines() -> None:
    result = get_module("dig").parse(out(DIG_OUTPUT), parse_target("example.com"))

    assert values(result, "A record") == ["93.184.216.34"]  # deduplicated
    assert values(result, "MX record") == ["10 mail.example.com."]
    assert values(result, "TXT record") == ["v=spf1 -all"]  # quotes stripped
    assert values(result, "PTR record") == ["host.example.com."]


def test_dig_ignores_comment_lines() -> None:
    result = get_module("dig").parse(out(DIG_OUTPUT), parse_target("example.com"))
    assert all("DiG" not in f.value for f in result.findings)


# -- sherlock ----------------------------------------------------------------

SHERLOCK_OUTPUT = """\
[*] Checking username some_user on:
[+] GitHub: https://github.com/some_user
[+] Reddit: https://reddit.com/user/some_user
[-] Twitter: Not Found!
"""


def test_sherlock_reports_only_hits() -> None:
    result = get_module("sherlock").parse(out(SHERLOCK_OUTPUT), parse_target("some_user"))

    urls = [
        f.value for f in result.findings if f.category == "account" and f.label != "Accounts found"
    ]
    assert urls == ["https://github.com/some_user", "https://reddit.com/user/some_user"]
    assert values(result, "Accounts found") == ["2"]


def test_sherlock_hits_are_notable() -> None:
    result = get_module("sherlock").parse(out(SHERLOCK_OUTPUT), parse_target("some_user"))
    assert result.findings[0].severity is Severity.NOTABLE


def test_sherlock_with_no_hits_is_empty() -> None:
    result = get_module("sherlock").parse(out("[-] Twitter: Not Found!\n"), parse_target("nobody"))
    assert result.findings == []


# -- subfinder ---------------------------------------------------------------


def test_subfinder_keeps_only_in_scope_hosts() -> None:
    body = "www.example.com\ndev.example.com\nexample.com\nunrelated.org\n"
    result = get_module("subfinder").parse(out(body), parse_target("example.com"))

    assert values(result, "Subdomain") == ["dev.example.com", "www.example.com"]


# -- theHarvester ------------------------------------------------------------


def test_theharvester_splits_emails_from_hosts() -> None:
    body = "bob@example.com\ncarol@other.com\nwww.example.com\n"
    result = get_module("theharvester").parse(out(body), parse_target("example.com"))

    assert values(result, "Email") == ["bob@example.com", "carol@other.com"]
    assert values(result, "Host") == ["www.example.com"]


def test_theharvester_marks_in_domain_emails_notable() -> None:
    body = "bob@example.com\ncarol@other.com\n"
    result = get_module("theharvester").parse(out(body), parse_target("example.com"))

    severities = {f.value: f.severity for f in result.findings}
    assert severities["bob@example.com"] is Severity.NOTABLE
    assert severities["carol@other.com"] is Severity.INFO


# -- availability ------------------------------------------------------------


def test_cli_module_is_unavailable_without_its_tool() -> None:
    availability = get_module("subfinder").availability(Settings())
    assert not availability.ok
    assert "subfinder" in availability.reason
    assert "go install" in availability.reason


def test_disabled_modules_report_as_unavailable() -> None:
    availability = get_module("dns").availability(Settings(disabled_modules=["dns"]))
    assert not availability.ok
    assert availability.reason == "disabled in settings"
