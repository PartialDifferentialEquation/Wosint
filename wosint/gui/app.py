"""Application bootstrap."""

from __future__ import annotations

import logging
import signal
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from ..core.settings import Settings
from .main_window import MainWindow
from .theme import STYLESHEET


def run_app(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    """Start the GUI and block until the window is closed.

    Returns:
        The Qt exit code, suitable for passing straight to :func:`sys.exit`.
    """
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("Wosint")
    app.setApplicationDisplayName("Wosint")
    app.setOrganizationName("Wosint")
    app.setStyleSheet(STYLESHEET)

    window = MainWindow(settings)
    window.show()

    # Qt swallows SIGINT unless the interpreter gets a chance to run; a idle
    # timer gives Ctrl+C in the launching terminal a chance to be noticed.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    heartbeat = QTimer()
    heartbeat.start(250)
    heartbeat.timeout.connect(lambda: None)

    logging.getLogger(__name__).debug("Wosint window shown")
    return app.exec()
