"""The assembled picture of a subject, built from every scan so far.

The findings table answers "what did this scan return?".  This panel answers the
question the analyst actually has -- "who is this?" -- by showing the merged
entities, what corroborates each one, and which leads are worth following next.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.correlate import Investigation, Pivot
from ...core.entities import Entity

#: Confidence at or above which an entity is shown as well corroborated.
STRONG_CONFIDENCE = 0.7


class ProfilePanel(QWidget):
    """Merged entities on the left, suggested next scans on the right.

    Signals:
        pivot_requested: Emitted with a :class:`Pivot` the analyst chose to
            follow, so the window can start that scan.
        status_message: Emitted with a short line for the status bar.
    """

    pivot_requested = Signal(object)
    status_message = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._investigation = Investigation()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_profile_side())
        splitter.addWidget(self._build_pivot_side())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([560, 380])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(splitter)

    # -- construction ------------------------------------------------------

    def _build_profile_side(self) -> QWidget:
        self.heading = QLabel("Nothing scanned yet")
        self.heading.setStyleSheet("font-weight: 600;")

        self.subheading = QLabel(
            "Scan a target and the things learned about it are collected here."
        )
        self.subheading.setObjectName("hint")
        self.subheading.setWordWrap(True)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Entity", "Corroboration", "Sources"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setUniformRowHeights(True)
        self.tree.itemDoubleClicked.connect(self._copy_item)
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setHighlightSections(False)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 4, 0)
        layout.addWidget(self.heading)
        layout.addWidget(self.subheading)
        layout.addWidget(self.tree, 1)
        return container

    def _build_pivot_side(self) -> QWidget:
        heading = QLabel("Follow next")
        heading.setStyleSheet("font-weight: 600;")

        self.pivot_hint = QLabel(
            "Identifiers found so far. Double-click one to scan it and fold the "
            "results into this profile."
        )
        self.pivot_hint.setObjectName("hint")
        self.pivot_hint.setWordWrap(True)

        self.pivot_tree = QTreeWidget()
        self.pivot_tree.setColumnCount(2)
        self.pivot_tree.setHeaderLabels(["Target", "Why"])
        self.pivot_tree.setRootIsDecorated(False)
        self.pivot_tree.setAlternatingRowColors(True)
        self.pivot_tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pivot_tree.itemDoubleClicked.connect(self._follow_item)
        pivot_header = self.pivot_tree.header()
        pivot_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        pivot_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        pivot_header.setHighlightSections(False)

        self.follow_button = QPushButton("Scan selected")
        self.follow_button.clicked.connect(self._follow_selected)
        self.clear_button = QPushButton("Start over")
        self.clear_button.setToolTip("Forget everything gathered so far and begin a new subject.")
        self.clear_button.clicked.connect(self.reset)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.addWidget(self.follow_button)
        buttons.addWidget(self.clear_button)
        buttons.addStretch(1)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 0, 0, 0)
        layout.addWidget(heading)
        layout.addWidget(self.pivot_hint)
        layout.addWidget(self.pivot_tree, 1)
        layout.addLayout(buttons)
        return container

    # -- state -------------------------------------------------------------

    @property
    def investigation(self) -> Investigation:
        return self._investigation

    def add_scan(self, scan) -> None:
        """Fold a completed scan into the profile and redraw."""
        self._investigation.add_scan(scan)
        self.refresh()

    def reset(self) -> None:
        """Forget everything and start a new subject."""
        self._investigation = Investigation()
        self.refresh()
        self.status_message.emit("Profile cleared.")

    def refresh(self) -> None:
        self._render_profile()
        self._render_pivots()

    # -- rendering ---------------------------------------------------------

    def _render_profile(self) -> None:
        self.tree.clear()
        grouped = self._investigation.summary()

        if not grouped:
            self.heading.setText("Nothing scanned yet")
            self.subheading.setText(
                "Scan a target and the things learned about it are collected here."
            )
            return

        scanned = self._investigation.scanned
        total = sum(len(v) for v in grouped.values())
        self.heading.setText(f"{total} things known about this subject")
        self.subheading.setText(
            f"Assembled from {len(scanned)} scan{'s' if len(scanned) != 1 else ''}: "
            + ", ".join(scanned)
        )

        for entity_type, entities in grouped.items():
            group = QTreeWidgetItem([f"{entity_type.label}  ({len(entities)})", "", ""])
            font = group.font(0)
            font.setBold(True)
            group.setFont(0, font)
            group.setFirstColumnSpanned(False)
            self.tree.addTopLevelItem(group)

            for entity in entities:
                group.addChild(self._entity_item(entity))
            group.setExpanded(True)

    def _entity_item(self, entity: Entity) -> QTreeWidgetItem:
        item = QTreeWidgetItem(
            [
                entity.display,
                f"{entity.confidence:.0%}",
                entity.corroboration,
            ]
        )
        item.setData(0, Qt.ItemDataRole.UserRole, entity.value)

        if entity.is_inferred:
            # Shown, but never as fact: this rests on a guess a module made,
            # and the analyst has to be able to see that at a glance.
            font = QFont()
            font.setItalic(True)
            item.setFont(0, font)
            for column in range(3):
                item.setForeground(column, QBrush(Qt.GlobalColor.darkGray))
        elif entity.confidence >= STRONG_CONFIDENCE:
            font = QFont()
            font.setBold(True)
            item.setFont(0, font)
            item.setForeground(1, QBrush(Qt.GlobalColor.green))
        else:
            item.setForeground(1, QBrush(Qt.GlobalColor.gray))

        # The tooltip is the audit trail: every claim, and who made it.
        lines = [f"{entity.type.label}: {entity.display}", ""]
        if entity.is_inferred:
            lines += [
                "Inferred, not confirmed. Every source for this was a guess, so "
                "it may belong to a different person.",
                "",
            ]
        lines += [
            f"· {source.label} — {source.module}"
            + (" [guess]" if source.inferred else "")
            + (f" (from {source.target})" if source.target else "")
            for source in entity.sources
        ]
        related = self._investigation.related_to(entity)
        if related:
            lines.append("")
            lines += [f"{relation.kind.label} {other.display}" for relation, other in related[:8]]
        item.setToolTip(0, "\n".join(lines))
        return item

    def _render_pivots(self) -> None:
        self.pivot_tree.clear()
        pivots = self._investigation.pivots()

        for pivot in pivots:
            label = f"{pivot.value}  ·  {pivot.type.label.lower()}"
            reason = pivot.reason + (" · already scanned" if pivot.scanned else "")
            item = QTreeWidgetItem([label, reason])
            item.setData(0, Qt.ItemDataRole.UserRole, pivot)
            if pivot.scanned:
                item.setForeground(0, QBrush(Qt.GlobalColor.gray))
                item.setForeground(1, QBrush(Qt.GlobalColor.gray))
            self.pivot_tree.addTopLevelItem(item)

        outstanding = sum(1 for p in pivots if not p.scanned)
        self.follow_button.setEnabled(bool(pivots))
        self.pivot_hint.setText(
            f"{outstanding} identifier{'s' if outstanding != 1 else ''} not yet scanned. "
            "Double-click one to follow it into this profile."
            if pivots
            else "Identifiers found during a scan appear here."
        )

    # -- interaction -------------------------------------------------------

    def selected_pivot(self) -> Pivot | None:
        item = self.pivot_tree.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item else None

    def _follow_selected(self) -> None:
        pivot = self.selected_pivot()
        if pivot is not None:
            self.pivot_requested.emit(pivot)

    def _follow_item(self, item: QTreeWidgetItem, _column: int) -> None:
        pivot = item.data(0, Qt.ItemDataRole.UserRole)
        if pivot is not None:
            self.pivot_requested.emit(pivot)

    def _copy_item(self, item: QTreeWidgetItem, column: int) -> None:
        value = item.data(0, Qt.ItemDataRole.UserRole) or item.text(column)
        if value:
            QGuiApplication.clipboard().setText(str(value))
            self.status_message.emit(f"Copied: {value}")
