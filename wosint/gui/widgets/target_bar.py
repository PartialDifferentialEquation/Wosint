"""The search bar: target entry, classification, and scan controls."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.targets import IMAGE_SUFFIXES, Target, TargetError, TargetType, coerce_target
from ...core.targets import parse_target as detect_target

#: Sentinel for the "work it out for me" entry in the type selector.
AUTO = "auto"

#: Types offered explicitly, in the order an analyst is likely to want them.
SELECTABLE_TYPES = (
    TargetType.PERSON,
    TargetType.USERNAME,
    TargetType.EMAIL,
    TargetType.PHONE,
    TargetType.IMAGE,
    TargetType.DOMAIN,
    TargetType.URL,
    TargetType.IPV4,
    TargetType.IPV6,
)

#: What a photograph is being examined for.
PHOTO_SUBJECTS = (
    ("Anything identifiable", "general"),
    ("Where it was taken", "location"),
    ("The people in it", "people"),
)

IMAGE_FILTER = "Images (" + " ".join(f"*{suffix}" for suffix in sorted(IMAGE_SUFFIXES)) + ")"


class TargetBar(QWidget):
    """Where the analyst says what they want to look into.

    The input is classified as it is typed, so it is clear whether
    ``bob@example.com`` was read as an email or something else *before* a scan
    starts. Detection has to take the safest reading of an ambiguous string,
    though -- a one-word name looks exactly like a username -- so the type
    selector is there to overrule it.

    Signals:
        scan_requested: Emitted with a valid :class:`Target`.
        cancel_requested: Emitted when the user stops a running scan.
        target_changed: Emitted with the current :class:`Target`, or ``None``
            when the input is empty or unusable.
    """

    scan_requested = Signal(object)
    cancel_requested = Signal()
    target_changed = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target: Target | None = None

        self.input = QLineEdit()
        self.input.setObjectName("targetInput")
        self.input.setPlaceholderText(
            "Name, username, email address, phone number, domain, IP, URL — or open a photo…"
        )
        self.input.setClearButtonEnabled(True)

        self.type_selector = QComboBox()
        self.type_selector.setToolTip(
            "Force how the target is read. Useful when a one-word name would "
            "otherwise be taken for a username."
        )
        self.type_selector.addItem("Detect type", AUTO)
        for target_type in SELECTABLE_TYPES:
            self.type_selector.addItem(target_type.label, target_type.value)
        self.type_selector.setMinimumWidth(150)

        self.browse_button = QPushButton("Open photo…")
        self.browse_button.setToolTip("Choose an image to examine (Ctrl+O)")

        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("primary")
        self.scan_button.setEnabled(False)
        self.scan_button.setDefault(True)

        self.cancel_button = QPushButton("Stop")
        self.cancel_button.setEnabled(False)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)
        top.addWidget(self.input, 1)
        top.addWidget(self.type_selector)
        top.addWidget(self.browse_button)
        top.addWidget(self.scan_button)
        top.addWidget(self.cancel_button)

        # The photo row only makes sense once the target is an image, so it
        # stays hidden rather than sitting there greyed out.
        self.photo_label = QLabel("This photo is being examined for:")
        self.photo_label.setObjectName("hint")
        self.subject_selector = QComboBox()
        for label, value in PHOTO_SUBJECTS:
            self.subject_selector.addItem(label, value)
        self.subject_selector.setToolTip(
            "Changes what the image-analysis module looks for. A street and a "
            "portrait are read for different things."
        )
        self.status = QLabel("")
        self.status.setObjectName("hint")

        self.photo_row = QWidget()
        photo_layout = QHBoxLayout(self.photo_row)
        photo_layout.setContentsMargins(0, 0, 0, 0)
        photo_layout.addWidget(self.photo_label)
        photo_layout.addWidget(self.subject_selector)
        photo_layout.addStretch(1)
        self.photo_row.setVisible(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addLayout(top)
        layout.addWidget(self.photo_row)
        layout.addWidget(self.status)

        self.input.textChanged.connect(self._reclassify)
        self.input.returnPressed.connect(self._emit_scan)
        self.type_selector.currentIndexChanged.connect(
            lambda _i: self._reclassify(self.input.text())
        )
        self.subject_selector.currentIndexChanged.connect(
            lambda _i: self._reclassify(self.input.text())
        )
        self.browse_button.clicked.connect(self.browse_for_image)
        self.scan_button.clicked.connect(self._emit_scan)
        self.cancel_button.clicked.connect(self.cancel_requested)

    # -- state -------------------------------------------------------------

    @property
    def target(self) -> Target | None:
        """The currently entered target, or ``None`` if it is unusable."""
        return self._target

    @property
    def chosen_type(self) -> TargetType | None:
        """The type the analyst forced, or ``None`` while detection is in charge."""
        data = self.type_selector.currentData()
        return None if data == AUTO else TargetType(data)

    @property
    def photo_subject(self) -> str:
        return str(self.subject_selector.currentData())

    def set_scanning(self, scanning: bool) -> None:
        """Swap the bar between idle and in-flight states."""
        self.scan_button.setEnabled(not scanning and self._target is not None)
        self.cancel_button.setEnabled(scanning)
        for widget in (self.input, self.type_selector, self.browse_button, self.subject_selector):
            widget.setEnabled(not scanning)

    def focus(self) -> None:
        self.input.setFocus()
        self.input.selectAll()

    def set_target_text(self, text: str) -> None:
        """Fill the box in as though it had been typed."""
        self.input.setText(text)

    def browse_for_image(self) -> str:
        """Ask for an image file and load it as the target.

        Returns:
            The chosen path, or an empty string if the dialog was dismissed.
        """
        path, _ = QFileDialog.getOpenFileName(self, "Open photo", str(Path.home()), IMAGE_FILTER)
        if not path:
            return ""
        self.select_type(TargetType.IMAGE)
        self.input.setText(path)
        return path

    def select_type(self, target_type: TargetType | None) -> None:
        """Set the type selector, or return it to automatic detection."""
        data = AUTO if target_type is None else target_type.value
        index = self.type_selector.findData(data)
        if index >= 0:
            self.type_selector.setCurrentIndex(index)

    # -- internals ---------------------------------------------------------

    def _reclassify(self, text: str) -> None:
        chosen = self.chosen_type
        hint = self.photo_subject

        if not text.strip():
            self._target = None
            self.status.setText("")
        else:
            try:
                self._target = (
                    coerce_target(text, chosen, hint=hint)
                    if chosen is not None
                    else detect_target(text, hint=hint)
                )
            except TargetError as exc:
                self._target = None
                self.status.setText(str(exc))
            else:
                self.status.setText(self._describe(self._target))

        is_image = self._target is not None and self._target.type is TargetType.IMAGE
        self.photo_row.setVisible(is_image)

        self.scan_button.setEnabled(self._target is not None and not self.cancel_button.isEnabled())
        self.target_changed.emit(self._target)

    def _describe(self, target: Target) -> str:
        """The line under the box explaining how the input was read."""
        if self.chosen_type is None:
            lead = f"Read as {target.type.label.lower()}"
        else:
            lead = f"Treating as {target.type.label.lower()}"
        if target.type is TargetType.IMAGE:
            return f"{lead}: {Path(target.value).name}"
        return f"{lead}: {target.value}"

    def _emit_scan(self) -> None:
        if self._target is not None and self.scan_button.isEnabled():
            self.scan_requested.emit(self._target)
