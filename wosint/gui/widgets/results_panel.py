"""The results area: findings, per-module status, and raw tool output."""

from __future__ import annotations

from PySide6.QtCore import QItemSelection, Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core.models import Finding, ModuleResult, Severity
from ..models import FindingFilterProxy, FindingTableModel, ModuleTableModel

#: Filter choices in the findings toolbar.
SEVERITY_FILTERS = (
    ("All findings", Severity.INFO),
    ("Notable and above", Severity.NOTABLE),
    ("Warnings only", Severity.WARNING),
)


class ResultsPanel(QWidget):
    """Three views of the same scan, on tabs.

    Signals:
        status_message: Emitted with a short line for the window's status bar.
    """

    status_message = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        #: Raw output keyed by module name; the combo box only holds labels.
        self._raw_cache: dict[str, str] = {}

        self.findings_model = FindingTableModel(self)
        self.proxy = FindingFilterProxy(self)
        self.proxy.setSourceModel(self.findings_model)
        self.modules_model = ModuleTableModel(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.tabs.addTab(self._build_modules_tab(), "Modules")
        self.tabs.addTab(self._build_raw_tab(), "Raw output")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.tabs)

    # -- construction ------------------------------------------------------

    def _build_findings_tab(self) -> QWidget:
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter findings…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.set_query)

        self.severity_filter = QComboBox()
        for label, _ in SEVERITY_FILTERS:
            self.severity_filter.addItem(label)
        self.severity_filter.currentIndexChanged.connect(
            lambda i: self.proxy.set_min_severity(SEVERITY_FILTERS[i][1])
        )

        self.count_label = QLabel("No findings yet")
        self.count_label.setObjectName("hint")

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.count_label)

        self.findings_table = QTableView()
        self.findings_table.setModel(self.proxy)
        self.findings_table.setSortingEnabled(True)
        self.findings_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        _configure_table(self.findings_table, stretch_column=3)
        self.findings_table.doubleClicked.connect(self._copy_cell)

        self.proxy.rowsInserted.connect(self._refresh_count)
        self.proxy.rowsRemoved.connect(self._refresh_count)
        self.proxy.modelReset.connect(self._refresh_count)
        self.proxy.layoutChanged.connect(self._refresh_count)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addLayout(toolbar)
        layout.addWidget(self.findings_table, 1)
        return container

    def _build_modules_tab(self) -> QWidget:
        self.modules_table = QTableView()
        self.modules_table.setModel(self.modules_model)
        _configure_table(self.modules_table, stretch_column=5)
        self.modules_table.selectionModel().selectionChanged.connect(self._on_module_selected)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        hint = QLabel("Select a module to jump to its raw output.")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        layout.addWidget(self.modules_table, 1)
        return container

    def _build_raw_tab(self) -> QWidget:
        self.raw_selector = QComboBox()
        self.raw_selector.currentIndexChanged.connect(self._show_selected_raw)

        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_view.setFont(QFont("monospace", 11))
        self.raw_view.setPlaceholderText("Raw tool and API output appears here once a scan runs.")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        header = QHBoxLayout()
        header.addWidget(QLabel("Module:"))
        header.addWidget(self.raw_selector, 1)
        layout.addLayout(header)
        layout.addWidget(self.raw_view, 1)
        return container

    # -- scan lifecycle ----------------------------------------------------

    def reset(self, results: list[ModuleResult]) -> None:
        """Clear the panel and seed it with the modules about to run."""
        self.findings_model.clear()
        self.modules_model.set_modules(results)
        self.raw_view.clear()
        self.raw_selector.blockSignals(True)
        self.raw_selector.clear()
        self.raw_selector.blockSignals(False)
        self._raw_cache.clear()
        self._refresh_count()
        _fit_columns(self.modules_table, stretch_column=5)

    def apply_result(self, result: ModuleResult) -> None:
        """Fold one module update into every view."""
        self.modules_model.update(result)
        if result.status.is_terminal:
            # A module can only report terminal state once per scan, but drop
            # any earlier rows first so a retry can never double up.
            self.findings_model.remove_module(result.module)
            self.findings_model.add_findings(result.findings, result.module)
            self._register_raw(result)
        self._refresh_count()
        self._fit_all_columns()

    def _fit_all_columns(self) -> None:
        """Re-fit both tables after new rows land."""
        _fit_columns(self.findings_table, stretch_column=3)
        _fit_columns(self.modules_table, stretch_column=5)

    def _register_raw(self, result: ModuleResult) -> None:
        if not result.raw:
            return
        label = f"{result.title} ({len(result.raw.splitlines())} lines)"
        existing = self.raw_selector.findData(result.module)
        if existing >= 0:
            self.raw_selector.setItemText(existing, label)
            self.raw_selector.setItemData(existing, result.raw, Qt.ItemDataRole.ToolTipRole)
        else:
            self.raw_selector.addItem(label, result.module)
        self._raw_cache[result.module] = result.raw
        if self.raw_selector.count() == 1:
            self._show_selected_raw(0)

    # -- interaction -------------------------------------------------------

    def show_module_raw(self, module: str) -> None:
        """Switch to the raw tab showing ``module``'s output."""
        index = self.raw_selector.findData(module)
        if index >= 0:
            self.raw_selector.setCurrentIndex(index)
            self.tabs.setCurrentIndex(2)

    def visible_findings(self) -> list[tuple[Finding, str]]:
        """The findings currently passing the filters, in display order."""
        rows = []
        for row in range(self.proxy.rowCount()):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            rows.append(self.findings_model.rows()[source.row()])
        return rows

    def _show_selected_raw(self, index: int) -> None:
        module = self.raw_selector.itemData(index)
        self.raw_view.setPlainText(self._raw_cache.get(module, ""))

    def _on_module_selected(self, selected: QItemSelection, _deselected: QItemSelection) -> None:
        indexes = selected.indexes()
        if not indexes:
            return
        result = self.modules_model.result_at(indexes[0].row())
        if result and result.raw:
            self.show_module_raw(result.module)

    def _copy_cell(self, index) -> None:
        """Double-clicking a cell copies it -- the common action on a finding."""
        value = index.data(Qt.ItemDataRole.DisplayRole)
        if value:
            QGuiApplication.clipboard().setText(str(value))
            self.status_message.emit(f"Copied: {value}")

    def _refresh_count(self, *_args) -> None:
        shown, total = self.proxy.rowCount(), self.findings_model.rowCount()
        if not total:
            self.count_label.setText("No findings yet")
        elif shown == total:
            self.count_label.setText(f"{total} findings")
        else:
            self.count_label.setText(f"{shown} of {total} findings")


#: Extra pixels added to a content-derived column width. Qt sizes columns from
#: the item delegate alone, which leaves no room for the cell padding the
#: stylesheet adds, so text ends up elided by a pixel or two without this.
COLUMN_PADDING = 16

#: No fixed column may take more than this, however long its content is.
MAX_FIXED_COLUMN_WIDTH = 260
#: Width the value column is kept above while there is any give elsewhere.
MIN_STRETCH_COLUMN_WIDTH = 320
#: Floor a fixed column will not be shrunk below.
MIN_COLUMN_WIDTH = 70


def _configure_table(table: QTableView, *, stretch_column: int) -> None:
    """Apply the table conventions shared by both result tables."""
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(24)
    header = table.horizontalHeader()
    # Interactive rather than ResizeToContents so the analyst can widen a
    # column and have it stay widened while results keep arriving.
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)
    header.setHighlightSections(False)
    header.setMinimumSectionSize(60)


def _fit_columns(table: QTableView, *, stretch_column: int) -> None:
    """Size the fixed columns to their content, keeping the value column usable.

    Fitting purely to content lets a few wide detail strings squeeze the
    stretch column -- the one holding the finding itself -- down to nothing.
    So each fixed column is capped, and if what remains for the value column is
    still too narrow, the widest fixed columns give width back until it is not.
    """
    model = table.model()
    if model is None:
        return

    fixed = [c for c in range(model.columnCount()) if c != stretch_column]
    widths = {
        column: min(
            max(table.sizeHintForColumn(column), _header_width(table, column)) + COLUMN_PADDING,
            MAX_FIXED_COLUMN_WIDTH,
        )
        for column in fixed
    }

    available = table.viewport().width()
    if available > 0:
        shortfall = (sum(widths.values()) + MIN_STRETCH_COLUMN_WIDTH) - available
        while shortfall > 0:
            widest = max(widths, key=lambda c: widths[c])
            if widths[widest] <= MIN_COLUMN_WIDTH:
                break
            take = min(shortfall, widths[widest] - MIN_COLUMN_WIDTH)
            widths[widest] -= take
            shortfall -= take

    for column, width in widths.items():
        table.setColumnWidth(column, width)


def _header_width(table: QTableView, column: int) -> int:
    header = table.horizontalHeader()
    return header.sectionSizeHint(column)
