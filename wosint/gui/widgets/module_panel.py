"""The module selection sidebar.

The list is filtered by target type: there is no point offering a username
lookup for an IP address, so modules that cannot handle the current target are
simply not shown.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.registry import all_modules
from ...core.settings import Settings
from ...core.targets import Target


class ModulePanel(QWidget):
    """Checkable list of the modules that apply to the current target.

    Signals:
        selection_changed: Emitted with the list of selected module names.
    """

    selection_changed = Signal(list)

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._target: Target | None = None
        #: Names the user explicitly unticked, remembered across target changes
        #: so a deselection is not silently undone by retyping the target.
        self._deselected: set[str] = set()

        self.heading = QLabel("Modules")
        self.heading.setStyleSheet("font-weight: 600;")

        self.summary = QLabel("Enter a target to see the applicable modules.")
        self.summary.setObjectName("hint")
        self.summary.setWordWrap(True)

        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.list.setUniformItemSizes(False)
        self.list.itemChanged.connect(self._on_item_changed)

        self.all_button = QPushButton("All")
        self.none_button = QPushButton("None")
        for button in (self.all_button, self.none_button):
            button.setFixedHeight(26)
        self.all_button.clicked.connect(lambda: self._set_all(True))
        self.none_button.clicked.connect(lambda: self._set_all(False))

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.addWidget(self.all_button)
        buttons.addWidget(self.none_button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self.heading)
        layout.addWidget(self.summary)
        layout.addLayout(buttons)
        layout.addWidget(self.list, 1)

    # -- state -------------------------------------------------------------

    def set_target(self, target: Target | None) -> None:
        """Rebuild the list for ``target``."""
        self._target = target
        self._rebuild()

    def selected_modules(self) -> list[str]:
        """Names of the ticked, runnable modules."""
        names = []
        for row in range(self.list.count()):
            item = self.list.item(row)
            if item.checkState() == Qt.CheckState.Checked:
                names.append(item.data(Qt.ItemDataRole.UserRole))
        return names

    def set_enabled_during_scan(self, scanning: bool) -> None:
        for widget in (self.list, self.all_button, self.none_button):
            widget.setEnabled(not scanning)

    # -- internals ---------------------------------------------------------

    def _rebuild(self) -> None:
        self.list.blockSignals(True)
        self.list.clear()

        if self._target is None:
            self.summary.setText("Enter a target to see the applicable modules.")
            self.list.blockSignals(False)
            self.selection_changed.emit([])
            return

        applicable = [m for m in all_modules() if m.supports(self._target)]
        unavailable = 0

        for module in applicable:
            availability = module.availability(self.settings)
            item = QListWidgetItem(f"{module.title}  ·  {module.kind}")
            item.setData(Qt.ItemDataRole.UserRole, module.name)
            tooltip = [module.description or module.title, _reach(module)]

            if availability.ok:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                should_check = module.default_enabled and module.name not in self._deselected
                item.setCheckState(
                    Qt.CheckState.Checked if should_check else Qt.CheckState.Unchecked
                )
            else:
                unavailable += 1
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                item.setCheckState(Qt.CheckState.Unchecked)
                item.setForeground(Qt.GlobalColor.gray)
                item.setText(f"{module.title}  ·  unavailable")
                tooltip.append(availability.reason)

            item.setToolTip("\n\n".join(tooltip))
            self.list.addItem(item)

        self.list.blockSignals(False)

        runnable = len(applicable) - unavailable
        kind = self._target.type.label.lower()
        message = f"{runnable} of {len(applicable)} modules can run against this {kind}"
        if unavailable:
            message += f" · {unavailable} need tools that are not installed"
        if self._target.is_personal:
            # Worth saying plainly: scanning a person is scanning personal data,
            # and most of these modules disclose the target to a third party in
            # the very act of asking about them.
            offline = sum(1 for m in applicable if not m.reaches_network)
            message += (
                f"\n\nThis target identifies a person. {offline} of these modules "
                "run offline; the rest disclose the target to the service they query."
            )
        self.summary.setText(message)
        self.selection_changed.emit(self.selected_modules())

    def _set_all(self, checked: bool) -> None:
        self.list.blockSignals(True)
        for row in range(self.list.count()):
            item = self.list.item(row)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                name = item.data(Qt.ItemDataRole.UserRole)
                self._deselected.discard(name) if checked else self._deselected.add(name)
        self.list.blockSignals(False)
        self.selection_changed.emit(self.selected_modules())

    def _on_item_changed(self, item: QListWidgetItem) -> None:
        name = item.data(Qt.ItemDataRole.UserRole)
        if item.checkState() == Qt.CheckState.Checked:
            self._deselected.discard(name)
        else:
            self._deselected.add(name)
        self.selection_changed.emit(self.selected_modules())


def _reach(module) -> str:
    """One line describing what leaves the machine when this module runs."""
    if not module.reaches_network:
        return "Runs offline. Nothing about the target is sent anywhere."
    source = getattr(module, "source_url", "") or getattr(module, "tool", "")
    if module.kind == "cli":
        return f"Runs {source} locally; that tool makes its own outbound requests."
    return f"Queries {source or 'a third-party service'}, disclosing the target to it."
