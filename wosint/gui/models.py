"""Qt item models backing the results tables.

Findings arrive module by module while a scan is in flight, so both models
support incremental insertion rather than being rebuilt on every update -- that
keeps the user's scroll position and selection intact as results land.
"""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont

from ..core.models import Finding, ModuleResult, Severity
from .theme import TEXT_MUTED, severity_colour, status_colour


class FindingTableModel(QAbstractTableModel):
    """Tabular view of every finding produced by a scan."""

    COLUMNS = ("Severity", "Category", "Field", "Value", "Detail", "Module")
    #: Role used by the proxy so sorting by severity is by rank, not by name.
    SORT_ROLE = int(Qt.ItemDataRole.UserRole) + 1

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[Finding, str]] = []

    # -- Qt model interface ------------------------------------------------

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        finding, module = self._rows[index.row()]
        column = index.column()

        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return (
                finding.severity.value,
                finding.category,
                finding.label,
                finding.value,
                finding.detail,
                module,
            )[column]

        if role == self.SORT_ROLE:
            # Severity sorts by rank; everything else sorts on its text.
            if column == 0:
                return finding.severity.rank
            return self.data(index, Qt.ItemDataRole.DisplayRole)

        if role == Qt.ItemDataRole.ForegroundRole:
            if finding.severity is Severity.INFO and column != 3:
                return QColor(TEXT_MUTED)
            return severity_colour(finding.severity)

        if role == Qt.ItemDataRole.FontRole and column == 3:
            font = QFont()
            font.setBold(finding.severity is not Severity.INFO)
            return font

        if role == Qt.ItemDataRole.ToolTipRole:
            parts = [f"{finding.label}: {finding.value}"]
            if finding.detail:
                parts.append(finding.detail)
            parts.append(f"from {module}")
            return "\n".join(parts)

        return None

    # -- mutation ----------------------------------------------------------

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def add_findings(self, findings: Iterable[Finding], module: str) -> None:
        """Append findings from one module."""
        new = [(finding, module) for finding in findings]
        if not new:
            return
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(new) - 1)
        self._rows.extend(new)
        self.endInsertRows()

    def remove_module(self, module: str) -> None:
        """Drop a module's rows, so a re-reported result does not duplicate them."""
        if not any(m == module for _, m in self._rows):
            return
        self.beginResetModel()
        self._rows = [row for row in self._rows if row[1] != module]
        self.endResetModel()

    def rows(self) -> list[tuple[Finding, str]]:
        return list(self._rows)


class FindingFilterProxy(QSortFilterProxyModel):
    """Free-text and severity filtering over :class:`FindingTableModel`.

    Re-filtering goes through :meth:`invalidate` rather than the
    ``invalidateFilter`` family, which Qt 6 deprecates -- and which, being
    called from a signal handler, would fail silently rather than loudly.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setSortRole(FindingTableModel.SORT_ROLE)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._min_severity = Severity.INFO
        self._query = ""

    def set_query(self, text: str) -> None:
        self._query = text.strip().lower()
        self.invalidate()

    def set_min_severity(self, severity: Severity) -> None:
        self._min_severity = severity
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return True
        finding, module = model.rows()[source_row]
        if finding.severity.rank < self._min_severity.rank:
            return False
        if not self._query:
            return True
        haystack = " ".join(
            (finding.category, finding.label, finding.value, finding.detail, module)
        ).lower()
        return self._query in haystack


class ModuleTableModel(QAbstractTableModel):
    """Live status of every module taking part in the current scan."""

    COLUMNS = ("Module", "Kind", "Status", "Findings", "Time", "Note")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._order: list[str] = []
        self._results: dict[str, ModuleResult] = {}

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._order)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        result = self._results[self._order[index.row()]]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return (
                result.title,
                result.kind.upper(),
                result.status.label,
                str(result.finding_count) if result.status.is_terminal else "",
                f"{result.duration_ms / 1000:.1f}s" if result.duration_ms else "",
                result.error,
            )[column]

        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 2:
                return status_colour(result.status)
            if column == 5 and result.error:
                return status_colour(result.status)
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            return result.error or result.title

        return None

    def set_modules(self, results: Iterable[ModuleResult]) -> None:
        """Replace the table contents at the start of a scan."""
        self.beginResetModel()
        self._order = []
        self._results = {}
        for result in results:
            self._order.append(result.module)
            self._results[result.module] = result
        self.endResetModel()

    def update(self, result: ModuleResult) -> None:
        """Refresh one module's row, adding it if the scan did not announce it."""
        if result.module not in self._results:
            row = len(self._order)
            self.beginInsertRows(QModelIndex(), row, row)
            self._order.append(result.module)
            self._results[result.module] = result
            self.endInsertRows()
            return
        self._results[result.module] = result
        row = self._order.index(result.module)
        self.dataChanged.emit(self.index(row, 0), self.index(row, self.columnCount() - 1))

    def result_at(self, row: int) -> ModuleResult | None:
        if 0 <= row < len(self._order):
            return self._results[self._order[row]]
        return None

    def results(self) -> list[ModuleResult]:
        return [self._results[name] for name in self._order]

    def clear(self) -> None:
        self.set_modules([])
