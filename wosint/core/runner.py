"""The scan engine.

:class:`ScanRunner` runs the selected modules against a target concurrently,
reporting each result as it lands rather than at the end, so a slow tool never
holds up the display of everything else.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterable

from ..modules.base import Module, ModuleOutput, RunContext
from .http import build_client
from .models import ModuleResult, ModuleStatus, Scan
from .process import ToolNotFound
from .registry import modules_for
from .settings import Settings
from .targets import Target

log = logging.getLogger(__name__)

#: Called with each :class:`ModuleResult` whenever its state changes.
ProgressCallback = Callable[[ModuleResult], None]


class ScanRunner:
    """Runs modules against a target and collects their results.

    The runner owns one HTTP client per scan and a semaphore that caps how many
    modules execute at once, which keeps a broad module selection from opening
    dozens of sockets and subprocesses simultaneously.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()

    async def run(
        self,
        target: Target,
        *,
        modules: Iterable[str] | None = None,
        on_update: ProgressCallback | None = None,
    ) -> Scan:
        """Scan ``target`` with the selected modules.

        Args:
            target: What to investigate.
            modules: Module names to run; ``None`` runs everything applicable.
            on_update: Invoked when a module starts and again when it finishes.
                Exceptions raised by the callback are logged and swallowed so a
                display bug cannot abort a scan.

        Returns:
            The completed :class:`Scan`, including modules that failed.
        """
        scan = Scan(target=target)
        selected = modules_for(target, names=modules)

        for module in selected:
            scan.results[module.name] = ModuleResult(
                module=module.name, title=module.title, kind=module.kind
            )

        if not selected:
            scan.finished_at = time.time()
            return scan

        semaphore = asyncio.Semaphore(max(1, self.settings.max_concurrency))
        async with build_client(self.settings) as client:
            ctx = RunContext(
                settings=self.settings,
                client=client,
                timeout=self.settings.module_timeout,
            )
            tasks = [
                asyncio.create_task(
                    self._run_one(module, target, ctx, scan, semaphore, on_update),
                    name=f"wosint-{module.name}",
                )
                for module in selected
            ]
            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                scan.cancelled = True
                for task in tasks:
                    task.cancel()
                # Let the cancellations settle so no subprocess is orphaned.
                await asyncio.gather(*tasks, return_exceptions=True)
                for result in scan.results.values():
                    if not result.status.is_terminal:
                        result.status = ModuleStatus.CANCELLED
                        self._notify(on_update, result)
                scan.finished_at = time.time()
                raise

        scan.finished_at = time.time()
        return scan

    async def _run_one(
        self,
        module: Module,
        target: Target,
        ctx: RunContext,
        scan: Scan,
        semaphore: asyncio.Semaphore,
        on_update: ProgressCallback | None,
    ) -> None:
        """Execute a single module, recording its outcome on ``scan``.

        Every failure mode is converted into a status on the result: one broken
        module must never take the rest of the scan with it.
        """
        result = scan.results[module.name]

        availability = module.availability(self.settings)
        if not availability:
            result.status = ModuleStatus.UNAVAILABLE
            result.error = availability.reason
            self._notify(on_update, result)
            return

        async with semaphore:
            result.status = ModuleStatus.RUNNING
            self._notify(on_update, result)

            started = time.perf_counter()
            try:
                output = await asyncio.wait_for(
                    module.execute(target, ctx), timeout=ctx.timeout + 5
                )
            except asyncio.CancelledError:
                result.status = ModuleStatus.CANCELLED
                result.duration_ms = int((time.perf_counter() - started) * 1000)
                self._notify(on_update, result)
                raise
            except (asyncio.TimeoutError, TimeoutError):
                result.status = ModuleStatus.TIMEOUT
                result.error = f"no response within {ctx.timeout:.0f}s"
            except ToolNotFound as exc:
                result.status = ModuleStatus.UNAVAILABLE
                result.error = str(exc)
            except Exception as exc:
                log.debug("module %s failed", module.name, exc_info=True)
                result.status = ModuleStatus.ERROR
                result.error = f"{type(exc).__name__}: {exc}"
            else:
                self._apply(result, output)

            result.duration_ms = int((time.perf_counter() - started) * 1000)
            self._notify(on_update, result)

    @staticmethod
    def _apply(result: ModuleResult, output: ModuleOutput) -> None:
        result.findings = output.findings
        result.raw = output.raw
        result.status = ModuleStatus.OK if output.findings else ModuleStatus.EMPTY

    @staticmethod
    def _notify(callback: ProgressCallback | None, result: ModuleResult) -> None:
        if callback is None:
            return
        try:
            callback(result)
        except Exception:
            log.warning("progress callback raised", exc_info=True)


async def scan_target(
    target: Target,
    *,
    settings: Settings | None = None,
    modules: Iterable[str] | None = None,
    on_update: ProgressCallback | None = None,
) -> Scan:
    """Convenience wrapper around :class:`ScanRunner` for one-off scans."""
    return await ScanRunner(settings).run(target, modules=modules, on_update=on_update)
