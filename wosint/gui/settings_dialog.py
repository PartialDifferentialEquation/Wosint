"""The advanced settings dialog.

Everything that changes how a scan behaves lives here: the API keys for modules
that need them, how hard the engine works, and the few details some sources
insist on knowing about the caller.

Keys entered here are written to the config file, which is created owner-only.
A key that came from the environment is shown but not editable -- the file value
would be ignored on the next load anyway, so letting it be typed over would be
a lie.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.registry import all_modules
from ..core.settings import Settings, config_path

#: Where to get a key for each module that needs one.
KEY_SOURCES = {
    "vision": "aistudio.google.com/apikey",
    "hibp": "haveibeenpwned.com/API/Key",
    "opensanctions": "www.opensanctions.org/api",
    "opencorporates": "opencorporates.com/api_accounts/new",
    "courtlistener": "www.courtlistener.com/help/api (optional: raises the rate limit)",
}


class SettingsDialog(QDialog):
    """Edit and persist :class:`~wosint.core.settings.Settings`.

    The dialog works on a copy and only writes it back when accepted, so
    cancelling really does leave the running configuration alone.
    """

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self._key_fields: dict[str, QLineEdit] = {}
        self._module_boxes: dict[str, QCheckBox] = {}

        self.setWindowTitle("Advanced settings")
        self.setMinimumWidth(680)
        self.resize(720, 620)

        tabs = QTabWidget()
        tabs.addTab(self._build_keys_tab(), "API keys")
        tabs.addTab(self._build_scanning_tab(), "Scanning")
        tabs.addTab(self._build_modules_tab(), "Modules")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        self.location_label = QLabel(f"Saved to {config_path()}")
        self.location_label.setObjectName("hint")
        self.location_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs, 1)
        layout.addWidget(self.location_label)
        layout.addWidget(buttons)

    # -- tabs --------------------------------------------------------------

    def _build_keys_tab(self) -> QWidget:
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        intro = QLabel(
            "Bring your own keys. Wosint stores these in your own config file and "
            "sends each one only to the service it belongs to. Modules without a "
            "key stay switched off rather than failing mid-scan."
        )
        intro.setObjectName("hint")
        intro.setWordWrap(True)
        form.addRow(intro)

        for module in all_modules():
            needs_key = getattr(module, "requires_key", False)
            optional = module.name in KEY_SOURCES and not needs_key
            if not needs_key and not optional:
                continue

            field = QLineEdit(self.settings.api_keys.get(module.name, ""))
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setPlaceholderText(
                "optional — raises the rate limit" if optional else "required for this module"
            )

            from_environment = self.settings.is_from_environment(module.name)
            if from_environment:
                field.setEnabled(False)
                field.setPlaceholderText("set by the environment")
                field.setToolTip(
                    f"Provided by WOSINT_KEY_{module.name.upper()}. The environment "
                    "wins over this file, so it cannot be changed here."
                )

            source = KEY_SOURCES.get(module.name, "")
            label = QLabel(f"{module.title}\n{source}" if source else module.title)
            label.setToolTip(module.description)

            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(field, 1)
            if from_environment:
                badge = QLabel("environment")
                badge.setObjectName("hint")
                row.addWidget(badge)

            container = QWidget()
            container.setLayout(row)
            form.addRow(label, container)
            self._key_fields[module.name] = field

        self.vision_model = QLineEdit(self.settings.vision_model)
        self.vision_model.setPlaceholderText("gemini-3.1-pro-preview")
        self.vision_model.setToolTip(
            "The model used for image analysis. Leave empty to use the default."
        )
        form.addRow("Image analysis model", self.vision_model)

        return _scrollable(form)

    def _build_scanning_tab(self) -> QWidget:
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        self.module_timeout = QDoubleSpinBox()
        self.module_timeout.setRange(5.0, 600.0)
        self.module_timeout.setSuffix(" s")
        self.module_timeout.setValue(self.settings.module_timeout)
        self.module_timeout.setToolTip("How long one module may run before it is stopped.")
        form.addRow("Module timeout", self.module_timeout)

        self.http_timeout = QDoubleSpinBox()
        self.http_timeout.setRange(1.0, 300.0)
        self.http_timeout.setSuffix(" s")
        self.http_timeout.setValue(self.settings.http_timeout)
        form.addRow("HTTP timeout", self.http_timeout)

        self.max_concurrency = QSpinBox()
        self.max_concurrency.setRange(1, 32)
        self.max_concurrency.setValue(self.settings.max_concurrency)
        self.max_concurrency.setToolTip("How many modules run at once.")
        form.addRow("Modules at once", self.max_concurrency)

        self.user_agent = QLineEdit(self.settings.user_agent)
        self.user_agent.setToolTip("Sent with every outbound HTTP request.")
        form.addRow("User agent", self.user_agent)

        self.contact_email = QLineEdit(self.settings.contact_email)
        self.contact_email.setPlaceholderText("you@example.com")
        self.contact_email.setToolTip(
            "Some public-records services require callers to identify themselves. "
            "The SEC will not serve requests without it."
        )
        form.addRow("Contact address", self.contact_email)

        self.phone_region = QLineEdit(self.settings.phone_region)
        self.phone_region.setPlaceholderText("GB, US, DE…")
        self.phone_region.setMaxLength(2)
        self.phone_region.setToolTip(
            "Used to read phone numbers typed without a country code. Leave empty "
            "and such numbers stay ambiguous rather than being guessed at."
        )
        form.addRow("Default phone region", self.phone_region)

        return _scrollable(form)

    def _build_modules_tab(self) -> QWidget:
        form = QFormLayout()

        intro = QLabel(
            "Unticked modules are hidden everywhere and never run, whatever the "
            "target. Use this to keep a source out of an investigation entirely."
        )
        intro.setObjectName("hint")
        intro.setWordWrap(True)
        form.addRow(intro)

        for module in all_modules():
            box = QCheckBox(f"{module.title}  ·  {module.kind}")
            box.setChecked(module.name not in self.settings.disabled_modules)
            box.setToolTip(f"{module.description}\n\n{_disclosure(module)}")
            form.addRow(box)
            self._module_boxes[module.name] = box

        return _scrollable(form)

    # -- persistence -------------------------------------------------------

    def apply_to(self, settings: Settings) -> None:
        """Copy the edited values onto ``settings``."""
        for name, field in self._key_fields.items():
            if settings.is_from_environment(name):
                continue
            settings.set_api_key(name, field.text())

        settings.vision_model = self.vision_model.text().strip()
        settings.module_timeout = float(self.module_timeout.value())
        settings.http_timeout = float(self.http_timeout.value())
        settings.max_concurrency = int(self.max_concurrency.value())
        settings.user_agent = self.user_agent.text().strip() or settings.user_agent
        settings.contact_email = self.contact_email.text().strip()
        settings.phone_region = self.phone_region.text().strip().upper()
        settings.disabled_modules = sorted(
            name for name, box in self._module_boxes.items() if not box.isChecked()
        )

    def accept(self) -> None:
        """Apply the edits to the live settings and write them out."""
        self.apply_to(self.settings)
        super().accept()


def _disclosure(module) -> str:
    """One line on what running this module discloses, and to whom."""
    if not module.reaches_network:
        return "Runs offline. Nothing about the target is sent anywhere."
    if module.kind == "cli":
        tool = getattr(module, "tool", "a local tool")
        return f"Runs {tool!r} locally, which queries third-party sources itself."
    source = getattr(module, "source_url", "") or "a third-party service"
    return f"Discloses the target to {source}."


def _scrollable(form: QFormLayout) -> QWidget:
    """Wrap a form so a long tab scrolls instead of stretching the dialog."""
    inner = QWidget()
    inner.setLayout(form)

    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QScrollArea.Shape.NoFrame)
    area.setWidget(inner)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    return area
