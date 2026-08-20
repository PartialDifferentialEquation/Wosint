"""The Wosint main window."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core.models import ModuleResult, ModuleStatus, Scan
from ..core.registry import modules_for
from ..core.settings import Settings
from ..core.targets import Target
from .controller import ScanController
from .widgets.module_panel import ModulePanel
from .widgets.results_panel import ResultsPanel
from .widgets.target_bar import TargetBar

log = logging.getLogger(__name__)

#: How long a transient status-bar message stays up.
STATUS_TIMEOUT_MS = 4000


class MainWindow(QMainWindow):
    """Ties the target bar, module panel, results panel and engine together."""

    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.settings = settings or Settings.load()
        self.controller = ScanController(self.settings, self)
        self._scan: Scan | None = None
        self._live_results: dict[str, ModuleResult] = {}

        self.setWindowTitle("Wosint")
        self.resize(1280, 820)

        self.target_bar = TargetBar()
        self.module_panel = ModulePanel(self.settings)
        self.results_panel = ResultsPanel()

        self._build_layout()
        self._build_menu()
        self._build_status_bar()
        self._connect()

        self.controller.start()
        self.target_bar.focus()

    # -- construction ------------------------------------------------------

    def _build_layout(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 12, 6, 12)
        sidebar_layout.addWidget(self.module_panel)
        splitter.addWidget(sidebar)

        main = QWidget()
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(6, 12, 12, 12)
        main_layout.setSpacing(10)
        main_layout.addWidget(self.target_bar)
        main_layout.addWidget(self.results_panel, 1)
        splitter.addWidget(main)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 960])
        self.setCentralWidget(splitter)

    def _build_menu(self) -> None:
        scan_menu = self.menuBar().addMenu("&Scan")

        self.action_run = QAction("&Run scan", self)
        self.action_run.setShortcut(QKeySequence("Ctrl+Return"))
        self.action_run.triggered.connect(self._start_scan)
        scan_menu.addAction(self.action_run)

        self.action_stop = QAction("&Stop scan", self)
        self.action_stop.setShortcut(QKeySequence("Ctrl+."))
        self.action_stop.setEnabled(False)
        self.action_stop.triggered.connect(self._cancel_scan)
        scan_menu.addAction(self.action_stop)

        scan_menu.addSeparator()

        focus = QAction("&Focus target box", self)
        focus.setShortcut(QKeySequence("Ctrl+L"))
        focus.triggered.connect(self.target_bar.focus)
        scan_menu.addAction(focus)

        scan_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        scan_menu.addAction(quit_action)

        export_menu = self.menuBar().addMenu("&Export")
        json_action = QAction("Export scan as &JSON…", self)
        json_action.setShortcut(QKeySequence("Ctrl+S"))
        json_action.triggered.connect(self._export_json)
        export_menu.addAction(json_action)

        csv_action = QAction("Export visible findings as &CSV…", self)
        csv_action.triggered.connect(self._export_csv)
        export_menu.addAction(csv_action)

        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("&About Wosint", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _build_status_bar(self) -> None:
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)
        self.summary_label = QLabel("Ready")
        self.statusBar().addWidget(self.summary_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

    def _connect(self) -> None:
        self.target_bar.scan_requested.connect(lambda _target: self._start_scan())
        self.target_bar.cancel_requested.connect(self._cancel_scan)
        self.target_bar.target_changed.connect(self.module_panel.set_target)

        self.controller.scan_started.connect(self._on_scan_started)
        self.controller.module_updated.connect(self._on_module_updated)
        self.controller.scan_finished.connect(self._on_scan_finished)
        self.controller.scan_failed.connect(self._on_scan_failed)

        self.results_panel.status_message.connect(
            lambda text: self.statusBar().showMessage(text, STATUS_TIMEOUT_MS)
        )
        self.module_panel.selection_changed.connect(self._on_selection_changed)

    # -- scan lifecycle ----------------------------------------------------

    def _start_scan(self) -> None:
        target = self.target_bar.target
        if target is None:
            self.statusBar().showMessage("Enter a valid target first.", STATUS_TIMEOUT_MS)
            return
        selected = self.module_panel.selected_modules()
        if not selected:
            self.statusBar().showMessage("Select at least one module.", STATUS_TIMEOUT_MS)
            return
        self.controller.submit(target, selected)

    def _cancel_scan(self) -> None:
        if self.controller.is_scanning:
            self.controller.cancel()
            self.statusBar().showMessage("Scan cancelled.", STATUS_TIMEOUT_MS)
            self._set_scanning(False)

    def _on_scan_started(self, target: Target) -> None:
        selected = self.module_panel.selected_modules()
        planned = [
            ModuleResult(module=m.name, title=m.title, kind=m.kind)
            for m in modules_for(target, names=selected)
        ]
        self._live_results = {r.module: r for r in planned}
        self.results_panel.reset(planned)
        self._set_scanning(True)
        self.progress.setRange(0, max(1, len(planned)))
        self.progress.setValue(0)
        self.setWindowTitle(f"Wosint — {target.value}")
        self.summary_label.setText(f"Scanning {target.value} with {len(planned)} modules…")

    def _on_module_updated(self, result: ModuleResult) -> None:
        self._live_results[result.module] = result
        self.results_panel.apply_result(result)
        done = sum(1 for r in self._live_results.values() if r.status.is_terminal)
        self.progress.setValue(done)
        if result.status is ModuleStatus.RUNNING:
            self.summary_label.setText(f"Running {result.title}…")

    def _on_scan_finished(self, scan: Scan) -> None:
        self._scan = scan
        self._set_scanning(False)
        if scan.cancelled:
            self.summary_label.setText("Scan cancelled.")
            return

        findings = sum(r.finding_count for r in self._live_results.values())
        failed = [r for r in self._live_results.values() if r.status is ModuleStatus.ERROR]
        parts = [
            f"{findings} findings from {len(self._live_results)} modules",
            f"{scan.duration_ms / 1000:.1f}s",
        ]
        if failed:
            parts.append(f"{len(failed)} module(s) failed — see the Modules tab")
        self.summary_label.setText(" · ".join(parts))
        QTimer.singleShot(1200, lambda: self.progress.setVisible(False))

    def _on_scan_failed(self, message: str) -> None:
        self._set_scanning(False)
        self.summary_label.setText("Scan failed.")
        QMessageBox.warning(self, "Scan failed", message)

    def _on_selection_changed(self, names: list[str]) -> None:
        if self.controller.is_scanning:
            return
        if self.target_bar.target is not None:
            self.summary_label.setText(f"{len(names)} modules selected")

    def _set_scanning(self, scanning: bool) -> None:
        self.target_bar.set_scanning(scanning)
        self.module_panel.set_enabled_during_scan(scanning)
        self.action_run.setEnabled(not scanning)
        self.action_stop.setEnabled(scanning)
        self.progress.setVisible(scanning or self.progress.isVisible())
        if scanning:
            self.progress.setVisible(True)

    # -- export ------------------------------------------------------------

    def _current_scan(self) -> Scan | None:
        """The finished scan, with the live per-module results folded in.

        Using the live results rather than the engine's copy means a cancelled
        or partially complete scan still exports whatever did come back.
        """
        if self._scan is None:
            return None
        self._scan.results.update(self._live_results)
        return self._scan

    def _export_json(self) -> None:
        scan = self._current_scan()
        if scan is None:
            self.statusBar().showMessage("Run a scan first.", STATUS_TIMEOUT_MS)
            return
        suggested = f"{scan.target.value.replace('/', '_')}-{scan.id}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export scan", suggested, "JSON (*.json)")
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(scan.as_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self.statusBar().showMessage(f"Exported to {path}", STATUS_TIMEOUT_MS)

    def _export_csv(self) -> None:
        rows = self.results_panel.visible_findings()
        if not rows:
            self.statusBar().showMessage("Nothing to export.", STATUS_TIMEOUT_MS)
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export findings", "findings.csv", "CSV (*.csv)"
        )
        if not path:
            return
        import csv

        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["severity", "category", "label", "value", "detail", "module"])
                for finding, module in rows:
                    writer.writerow(
                        [
                            finding.severity.value,
                            finding.category,
                            finding.label,
                            finding.value,
                            finding.detail,
                            module,
                        ]
                    )
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self.statusBar().showMessage(f"Exported {len(rows)} findings to {path}", STATUS_TIMEOUT_MS)

    def _show_about(self) -> None:
        from .. import __version__

        QMessageBox.about(
            self,
            "About Wosint",
            f"<b>Wosint {__version__}</b><br><br>"
            "A desktop OSINT workbench that runs local command line tools and "
            "public web APIs against one target and collects the results in a "
            "single view.<br><br>"
            "Only use it against infrastructure you own or are authorised to "
            "assess.",
        )

    # -- window ------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the engine thread before the window goes away."""
        self.controller.shutdown()
        super().closeEvent(event)
