"""OSINT modules.

Importing this package registers every module with
:mod:`wosint.core.registry`; nothing else needs to know the individual module
names.  New modules only need to be added to the import list below.
"""

from . import (
    api_crtsh,
    api_dns,
    api_geoip,
    api_hackertarget,
    api_rdap,
    api_wayback,
    cli_dig,
    cli_sherlock,
    cli_subfinder,
    cli_theharvester,
    cli_whois,
)
from .base import ApiModule, CliModule, Module, ModuleOutput, RunContext

__all__ = ["ApiModule", "CliModule", "Module", "ModuleOutput", "RunContext"]
