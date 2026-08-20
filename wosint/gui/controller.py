"""The bridge between the asyncio scan engine and the Qt event loop.

Qt widgets may only be touched from the GUI thread, while the engine is
asyncio and wants a loop of its own.  :class:`ScanController` owns a background
thread running an event loop, submits scans onto it, and reports progress back
as Qt signals -- which Qt delivers as queued calls on the GUI thread, so no
widget is ever touched from the worker.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import threading
from collections.abc import Iterable
from concurrent.futures import Future

from PySide6.QtCore import QObject, Signal

from ..core.models import ModuleResult, Scan
from ..core.runner import ScanRunner
from ..core.settings import Settings
from ..core.targets import Target

log = logging.getLogger(__name__)


class ScanController(QObject):
    """Runs scans off the GUI thread and reports progress as signals.

    Signals:
        scan_started: Emitted with the :class:`Target` when a scan begins.
        module_updated: Emitted with a *copy* of a :class:`ModuleResult` each
            time it changes state. The copy matters: the engine keeps mutating
            the original on the worker thread while the GUI renders it.
        scan_finished: Emitted with the completed :class:`Scan`.
        scan_failed: Emitted with a human-readable message if a scan could not
            be run at all.
    """

    scan_started = Signal(object)
    module_updated = Signal(object)
    scan_finished = Signal(object)
    scan_failed = Signal(str)

    def __init__(self, settings: Settings | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.settings = settings or Settings.load()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._future: Future | None = None
        #: Whether a scan is in flight. Tracked explicitly rather than read off
        #: the future, because the terminal signals are emitted from *inside*
        #: the coroutine -- so the future is still "not done" while a handler
        #: reacting to scan_finished runs, and anything gated on it would be
        #: wrongly refused at exactly the moment the user acts on a result.
        self._active = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Spin up the engine thread. Safe to call more than once."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run_loop, name="wosint-engine", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("scan engine thread failed to start")

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            # Give cancelled scans a chance to reap their subprocesses before
            # the loop closes underneath them.
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Cancel any running scan and stop the engine thread."""
        self.cancel()
        loop, thread = self._loop, self._thread
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=timeout)
        self._loop = None
        self._thread = None
        self._ready.clear()

    # -- scanning ----------------------------------------------------------

    @property
    def is_scanning(self) -> bool:
        return self._active

    def submit(self, target: Target, modules: Iterable[str] | None = None) -> None:
        """Queue a scan of ``target``.

        A scan already in flight is cancelled first, so hitting Enter twice
        replaces the running scan rather than piling a second one on top of it.
        """
        if self._loop is None:
            self.start()
        assert self._loop is not None

        self.cancel()
        names = list(modules) if modules is not None else None
        self._future = asyncio.run_coroutine_threadsafe(self._scan(target, names), self._loop)

    def cancel(self) -> None:
        """Cancel the running scan, if there is one."""
        future, self._future = self._future, None
        self._active = False
        if future is not None and not future.done():
            future.cancel()

    async def _scan(self, target: Target, modules: list[str] | None) -> None:
        self.scan_started.emit(target)
        runner = ScanRunner(self.settings)
        try:
            scan = await runner.run(target, modules=modules, on_update=self._on_update)
        except asyncio.CancelledError:
            log.debug("scan of %s cancelled", target.value)
            self.scan_finished.emit(self._cancelled_scan(target))
            raise
        except Exception as exc:
            log.exception("scan of %s failed", target.value)
            self.scan_failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.scan_finished.emit(scan)

    def _on_update(self, result: ModuleResult) -> None:
        """Forward a progress update to the GUI thread.

        The engine mutates ``result`` in place as the module progresses, so a
        snapshot is emitted instead of the live object.
        """
        self.module_updated.emit(copy.deepcopy(result))

    @staticmethod
    def _cancelled_scan(target: Target) -> Scan:
        scan = Scan(target=target)
        scan.cancelled = True
        scan.finished_at = scan.started_at
        return scan
