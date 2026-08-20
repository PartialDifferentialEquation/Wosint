"""Subprocess execution: injection safety, timeouts and missing tools."""

from __future__ import annotations

import asyncio

import pytest

from wosint.core.process import ToolNotFound, run_command, tool_available


async def test_captures_stdout() -> None:
    result = await run_command(["echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"


async def test_arguments_are_never_shell_interpreted() -> None:
    """A target containing shell metacharacters stays one inert argument."""
    hostile = "example.com; touch /tmp/wosint-pwned"
    result = await run_command(["echo", hostile])
    assert result.stdout.strip() == hostile


async def test_reports_nonzero_exit() -> None:
    result = await run_command(["sh", "-c", "exit 3"])
    assert not result.ok
    assert result.returncode == 3


async def test_missing_tool_raises() -> None:
    with pytest.raises(ToolNotFound) as excinfo:
        await run_command(["wosint-tool-that-does-not-exist"])
    assert excinfo.value.tool == "wosint-tool-that-does-not-exist"


async def test_timeout_kills_the_process() -> None:
    with pytest.raises(asyncio.TimeoutError):
        await run_command(["sleep", "10"], timeout=0.3)


async def test_timeout_reaps_the_process_group() -> None:
    """A tool that spawns children must not leave them running."""
    with pytest.raises(asyncio.TimeoutError):
        await run_command(["sh", "-c", "sleep 30 & sleep 30"], timeout=0.3)


async def test_stdin_is_forwarded() -> None:
    result = await run_command(["cat"], stdin="piped input")
    assert result.stdout == "piped input"


async def test_empty_args_rejected() -> None:
    with pytest.raises(ValueError):
        await run_command([])


def test_tool_available() -> None:
    assert tool_available("echo")
    assert not tool_available("wosint-tool-that-does-not-exist")


async def test_text_combines_streams() -> None:
    result = await run_command(["sh", "-c", "echo out; echo err >&2"])
    assert "out" in result.text
    assert "err" in result.text
