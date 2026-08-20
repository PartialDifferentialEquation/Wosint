"""Safe execution of external command line tools.

Every CLI module goes through :func:`run_command`.  Commands are always passed
as an argument list and never through a shell, so a target such as
``example.com; rm -rf ~`` is handed to the tool as one inert argument rather
than being interpreted.  Targets are additionally validated by
:mod:`wosint.core.targets` before they ever reach this module.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
from dataclasses import dataclass


class ToolNotFound(RuntimeError):
    """Raised when the requested executable is not on ``PATH``."""

    def __init__(self, tool: str) -> None:
        super().__init__(f"{tool!r} is not installed or not on PATH")
        self.tool = tool


@dataclass(frozen=True, slots=True)
class CommandOutput:
    """The result of one subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        """Combined output, preferring stdout but never losing stderr."""
        if self.stdout and self.stderr:
            return f"{self.stdout.rstrip()}\n\n[stderr]\n{self.stderr.rstrip()}"
        return (self.stdout or self.stderr).rstrip()


def tool_available(tool: str) -> bool:
    """Whether ``tool`` can be found on ``PATH``."""
    return shutil.which(tool) is not None


async def run_command(
    args: list[str],
    *,
    timeout: float = 45.0,
    stdin: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandOutput:
    """Run ``args`` and capture its output.

    Args:
        args: Executable and arguments. Never passed through a shell.
        timeout: Seconds before the process group is terminated.
        stdin: Optional text written to the process' standard input.
        env: Extra environment variables layered over the current environment.

    Raises:
        ToolNotFound: If ``args[0]`` is not on ``PATH``.
        asyncio.TimeoutError: If the process outlives ``timeout``.
    """
    if not args:
        raise ValueError("run_command() needs at least an executable name")
    if not tool_available(args[0]):
        raise ToolNotFound(args[0])

    child_env = {**os.environ, **(env or {})}
    # Tools that colourise output produce escape codes that are noise once the
    # text lands in a Qt text view.
    child_env.setdefault("NO_COLOR", "1")

    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=child_env,
        start_new_session=True,
    )

    payload = stdin.encode() if stdin is not None else None
    try:
        out, err = await asyncio.wait_for(process.communicate(payload), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        await _terminate(process)
        raise

    return CommandOutput(
        returncode=process.returncode or 0,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
    )


async def _terminate(process: asyncio.subprocess.Process) -> None:
    """Stop a runaway process, escalating to SIGKILL if it ignores SIGTERM.

    ``start_new_session=True`` puts the child in its own process group, so
    signalling the group also reaps helpers that the tool itself spawned.
    """
    if process.returncode is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
            return
        except asyncio.TimeoutError:
            continue
