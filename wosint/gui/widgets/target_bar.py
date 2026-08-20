"""The search bar: target entry, live classification, and scan controls."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QWidget

from ...core.targets import Target, TargetError, parse_target


class TargetBar(QWidget):
    """Where the analyst types what they want to look into.

    The input is classified as the user types so they can see whether Wosint
    read ``bob@example.com`` as an email or a username *before* starting a
    scan, and the scan button stays disabled until the input makes sense.

    Signals:
        scan_requested: Emitted with a valid :class:`Target`.
        cancel_requested: Emitted when the user stops a running scan.
        target_changed: Emitted with the current :class:`Target`, or ``None``
            when the input is empty or unparseable.
    """

    scan_requested = Signal(object)
    cancel_requested = Signal()
    target_changed = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target: Target | None = None

        self.input = QLineEdit()
        self.input.setObjectName("targetInput")
        self.input.setPlaceholderText("Domain, IP address, URL, email address or username…")
        self.input.setClearButtonEnabled(True)

        self.badge = QLabel("—")
        self.badge.setObjectName("targetBadge")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setMinimumWidth(112)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("primary")
        self.scan_button.setEnabled(False)
        self.scan_button.setDefault(True)

        self.cancel_button = QPushButton("Stop")
        self.cancel_button.setEnabled(False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self.input, 1)
        layout.addWidget(self.badge)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.cancel_button)

        self.input.textChanged.connect(self._reclassify)
        self.input.returnPressed.connect(self._emit_scan)
        self.scan_button.clicked.connect(self._emit_scan)
        self.cancel_button.clicked.connect(self.cancel_requested)

    # -- state -------------------------------------------------------------

    @property
    def target(self) -> Target | None:
        """The currently entered target, or ``None`` if the input is invalid."""
        return self._target

    def set_scanning(self, scanning: bool) -> None:
        """Swap the bar between idle and in-flight states."""
        self.scan_button.setEnabled(not scanning and self._target is not None)
        self.cancel_button.setEnabled(scanning)
        self.input.setEnabled(not scanning)

    def focus(self) -> None:
        self.input.setFocus()
        self.input.selectAll()

    # -- internals ---------------------------------------------------------

    def _reclassify(self, text: str) -> None:
        try:
            self._target = parse_target(text)
        except TargetError as exc:
            self._target = None
            self.badge.setText("—" if not text.strip() else "unrecognised")
            self.badge.setToolTip("" if not text.strip() else str(exc))
        else:
            self.badge.setText(self._target.type.label)
            self.badge.setToolTip(f"Will be scanned as: {self._target.value}")

        self.scan_button.setEnabled(self._target is not None and not self.cancel_button.isEnabled())
        self.target_changed.emit(self._target)

    def _emit_scan(self) -> None:
        if self._target is not None and self.scan_button.isEnabled():
            self.scan_requested.emit(self._target)
