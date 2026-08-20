"""OSINT modules.

Importing this package registers every module with
:mod:`wosint.core.registry`; nothing else needs to know the individual module
names.  New modules only need to be added to the import list below.
"""

from . import (
    api_crtsh,
    api_dns,
    api_forge,
    api_geoip,
    api_gravatar,
    api_hackertarget,
    api_hibp,
    api_rdap,
    api_wayback,
    cli_dig,
    cli_holehe,
    cli_maigret,
    cli_phoneinfoga,
    cli_sherlock,
    cli_subfinder,
    cli_theharvester,
    cli_whois,
    local_email,
    local_links,
    local_phone,
)
from .base import ApiModule, CliModule, LocalModule, Module, ModuleOutput, RunContext

__all__ = [
    "ApiModule",
    "CliModule",
    "LocalModule",
    "Module",
    "ModuleOutput",
    "RunContext",
]
