"""Application palette and stylesheet.

A dark theme is the default because Wosint sits alongside terminals and other
security tooling, and because the severity colours read better against it.
"""

from __future__ import annotations

from PySide6.QtGui import QColor

from ..core.models import ModuleStatus, Severity

BACKGROUND = "#14161a"
SURFACE = "#1b1e24"
SURFACE_ALT = "#22262e"
BORDER = "#2e333d"
TEXT = "#dfe3ea"
TEXT_MUTED = "#8a93a3"
ACCENT = "#4c8dff"

#: Row foreground per severity, from calm to loud.
SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.INFO: TEXT,
    Severity.NOTABLE: "#f2c14e",
    Severity.WARNING: "#ff6b6b",
}

#: Status text colour in the module list.
STATUS_COLOURS: dict[ModuleStatus, str] = {
    ModuleStatus.PENDING: TEXT_MUTED,
    ModuleStatus.RUNNING: ACCENT,
    ModuleStatus.OK: "#5ec27a",
    ModuleStatus.EMPTY: TEXT_MUTED,
    ModuleStatus.ERROR: "#ff6b6b",
    ModuleStatus.TIMEOUT: "#f2c14e",
    ModuleStatus.UNAVAILABLE: TEXT_MUTED,
    ModuleStatus.SKIPPED: TEXT_MUTED,
    ModuleStatus.CANCELLED: TEXT_MUTED,
}


def severity_colour(severity: Severity) -> QColor:
    return QColor(SEVERITY_COLOURS.get(severity, TEXT))


def status_colour(status: ModuleStatus) -> QColor:
    return QColor(STATUS_COLOURS.get(status, TEXT))


STYLESHEET = f"""
QWidget {{
    background: {BACKGROUND};
    color: {TEXT};
    font-size: 13px;
}}
QMainWindow::separator {{ background: {BORDER}; width: 1px; height: 1px; }}

QLineEdit, QPlainTextEdit, QTextEdit,
QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QPlainTextEdit:focus,
QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit#targetInput {{ font-size: 15px; padding: 9px 12px; }}

QPushButton {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 16px;
}}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER}; }}
QPushButton#primary {{
    background: {ACCENT}; border-color: {ACCENT};
    color: #08101f; font-weight: 600;
}}
QPushButton#primary:hover {{ background: #679fff; }}
QPushButton#primary:disabled {{
    background: {SURFACE_ALT}; color: {TEXT_MUTED}; border-color: {BORDER};
}}

QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 10px;
    font-weight: 600;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {TEXT_MUTED}; }}

QTableView, QTreeView, QListWidget {{
    background: {SURFACE};
    alternate-background-color: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: {BORDER};
    selection-background-color: #2b4d87;
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {SURFACE_ALT};
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 7px 8px;
    font-weight: 600;
}}
QListWidget::item {{ padding: 4px 2px; }}

QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED};
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom-color: {ACCENT}; }}

QProgressBar {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
    text-align: center;
    max-height: 16px;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

QStatusBar {{ border-top: 1px solid {BORDER}; color: {TEXT_MUTED}; }}
QMenuBar {{ background: {SURFACE}; border-bottom: 1px solid {BORDER}; }}
QMenuBar::item:selected {{ background: {SURFACE_ALT}; }}
QMenu {{ background: {SURFACE}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {SURFACE_ALT}; }}

QScrollBar:vertical, QScrollBar:horizontal {{ background: transparent; width: 10px; height: 10px; }}
QScrollBar::handle {{
    background: {BORDER}; border-radius: 5px; min-height: 26px; min-width: 26px;
}}
QScrollBar::handle:hover {{ background: #3d4450; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}

QLabel#hint {{ color: {TEXT_MUTED}; }}
QLabel#targetBadge {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 3px 10px;
    color: {TEXT_MUTED};
}}
"""
