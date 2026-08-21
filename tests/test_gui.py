"""GUI tests, run against Qt's offscreen platform.

These exercise the widgets and the Qt models directly; the engine is replaced
with hand-built results so nothing here touches the network.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="PySide6 is not installed")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from wosint.core.models import Finding, ModuleResult, ModuleStatus, Severity
from wosint.core.settings import Settings
from wosint.core.targets import TargetType, parse_target
from wosint.gui.models import FindingFilterProxy, FindingTableModel, ModuleTableModel
from wosint.gui.widgets.module_panel import ModulePanel
from wosint.gui.widgets.results_panel import ResultsPanel
from wosint.gui.widgets.target_bar import TargetBar


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def findings() -> list[Finding]:
    return [
        Finding("dns", "A record", "1.2.3.4", "TTL 300s"),
        Finding("dns", "Mail policy", "no SPF record", "spoofable", Severity.WARNING),
        Finding("certificate", "Subdomain", "dev.example.com", "", Severity.NOTABLE),
    ]


# -- target bar --------------------------------------------------------------


def test_target_bar_classifies_as_you_type(qapp) -> None:
    bar = TargetBar()

    bar.input.setText("example.com")
    assert bar.target.type is TargetType.DOMAIN
    assert "Read as domain" in bar.status.text()
    assert bar.scan_button.isEnabled()

    bar.input.setText("bob@example.com")
    assert bar.target.type is TargetType.EMAIL

    bar.input.setText("1.2.3.4")
    assert bar.target.type is TargetType.IPV4


def test_target_bar_disables_scanning_for_invalid_input(qapp) -> None:
    bar = TargetBar()
    bar.input.setText("not a target!")

    assert bar.target is None
    assert "Could not work out" in bar.status.text()
    assert not bar.scan_button.isEnabled()


def test_target_bar_emits_only_valid_targets(qapp) -> None:
    bar = TargetBar()
    emitted = []
    bar.scan_requested.connect(emitted.append)

    bar.input.setText("not a target!")
    bar.scan_button.click()
    assert emitted == []

    bar.input.setText("example.com")
    bar.scan_button.click()
    assert [t.value for t in emitted] == ["example.com"]


def test_target_bar_locks_input_while_scanning(qapp) -> None:
    bar = TargetBar()
    bar.input.setText("example.com")

    bar.set_scanning(True)
    assert not bar.scan_button.isEnabled()
    assert bar.cancel_button.isEnabled()
    assert not bar.input.isEnabled()

    bar.set_scanning(False)
    assert bar.scan_button.isEnabled()
    assert not bar.cancel_button.isEnabled()


# -- module panel ------------------------------------------------------------


def test_module_panel_lists_only_applicable_modules(qapp) -> None:
    panel = ModulePanel(Settings())

    panel.set_target(parse_target("1.2.3.4"))
    ip_modules = {
        panel.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(panel.list.count())
    }

    assert "geoip" in ip_modules
    assert "crtsh" not in ip_modules  # certificates are a domain concept
    assert "sherlock" not in ip_modules


def test_module_panel_disables_modules_whose_tool_is_missing(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("example.com"))

    for row in range(panel.list.count()):
        item = panel.list.item(row)
        if item.data(Qt.ItemDataRole.UserRole) == "whois":
            assert not (item.flags() & Qt.ItemFlag.ItemIsUserCheckable)
            assert "unavailable" in item.text()
            return
    pytest.fail("whois was not listed for a domain target")


def test_module_panel_remembers_deselection_across_targets(qapp) -> None:
    """Retyping a target must not silently re-tick a module the user turned off."""
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("example.com"))
    assert "dns" in panel.selected_modules()

    for row in range(panel.list.count()):
        item = panel.list.item(row)
        if item.data(Qt.ItemDataRole.UserRole) == "dns":
            item.setCheckState(Qt.CheckState.Unchecked)

    panel.set_target(parse_target("other.example"))
    assert "dns" not in panel.selected_modules()


def test_module_panel_select_all_and_none(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("example.com"))

    panel.none_button.click()
    assert panel.selected_modules() == []

    panel.all_button.click()
    assert "dns" in panel.selected_modules()
    assert "whois" not in panel.selected_modules()  # unavailable, so never ticked


def test_module_panel_clears_for_no_target(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("example.com"))
    panel.set_target(None)

    assert panel.list.count() == 0
    assert panel.selected_modules() == []


# -- table models ------------------------------------------------------------


def test_finding_model_exposes_every_column(qapp, findings) -> None:
    model = FindingTableModel()
    model.add_findings(findings, "dns")

    assert model.rowCount() == 3
    row = [model.data(model.index(0, c)) for c in range(model.columnCount())]
    assert row == ["info", "dns", "A record", "1.2.3.4", "TTL 300s", "dns"]


def test_finding_model_sorts_severity_by_rank_not_alphabetically(qapp, findings) -> None:
    model = FindingTableModel()
    model.add_findings(findings, "dns")
    proxy = FindingFilterProxy()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.DescendingOrder)

    assert proxy.data(proxy.index(0, 0)) == "warning"
    assert proxy.data(proxy.index(2, 0)) == "info"


def test_finding_filter_matches_any_column(qapp, findings) -> None:
    model = FindingTableModel()
    model.add_findings(findings, "crtsh")
    proxy = FindingFilterProxy()
    proxy.setSourceModel(model)

    proxy.set_query("dev.example")
    assert proxy.rowCount() == 1

    proxy.set_query("crtsh")
    assert proxy.rowCount() == 3

    proxy.set_query("")
    assert proxy.rowCount() == 3


def test_finding_filter_applies_severity_floor(qapp, findings) -> None:
    model = FindingTableModel()
    model.add_findings(findings, "dns")
    proxy = FindingFilterProxy()
    proxy.setSourceModel(model)

    proxy.set_min_severity(Severity.NOTABLE)
    assert proxy.rowCount() == 2

    proxy.set_min_severity(Severity.WARNING)
    assert proxy.rowCount() == 1


def test_finding_model_replaces_a_module_rather_than_duplicating(qapp, findings) -> None:
    model = FindingTableModel()
    model.add_findings(findings, "dns")
    model.remove_module("dns")
    model.add_findings(findings, "dns")

    assert model.rowCount() == 3


def test_module_model_updates_a_row_in_place(qapp) -> None:
    model = ModuleTableModel()
    model.set_modules([ModuleResult(module="dns", title="DNS records", kind="api")])

    updated = ModuleResult(
        module="dns",
        title="DNS records",
        kind="api",
        status=ModuleStatus.OK,
        findings=[Finding("dns", "A record", "1.2.3.4")],
        duration_ms=1200,
    )
    model.update(updated)

    assert model.rowCount() == 1
    assert model.data(model.index(0, 2)) == "Done"
    assert model.data(model.index(0, 3)) == "1"
    assert model.data(model.index(0, 4)) == "1.2s"


def test_module_model_adds_unannounced_modules(qapp) -> None:
    model = ModuleTableModel()
    model.set_modules([])
    model.update(ModuleResult(module="late", title="Late", kind="api"))
    assert model.rowCount() == 1


# -- results panel -----------------------------------------------------------


def test_results_panel_folds_in_a_completed_module(qapp, findings) -> None:
    panel = ResultsPanel()
    panel.reset([ModuleResult(module="dns", title="DNS records", kind="api")])

    panel.apply_result(
        ModuleResult(
            module="dns",
            title="DNS records",
            kind="api",
            status=ModuleStatus.OK,
            findings=findings,
            raw="raw dns output",
        )
    )

    assert panel.findings_model.rowCount() == 3
    assert panel.count_label.text() == "3 findings"
    assert panel.raw_selector.count() == 1


def test_results_panel_ignores_in_flight_updates(qapp, findings) -> None:
    """A RUNNING update refreshes status but must not add findings yet."""
    panel = ResultsPanel()
    panel.reset([ModuleResult(module="dns", title="DNS records", kind="api")])

    panel.apply_result(
        ModuleResult(module="dns", title="DNS records", kind="api", status=ModuleStatus.RUNNING)
    )

    assert panel.findings_model.rowCount() == 0
    assert panel.modules_model.data(panel.modules_model.index(0, 2)) == "Running"


def test_results_panel_reset_clears_previous_scan(qapp, findings) -> None:
    panel = ResultsPanel()
    panel.reset([ModuleResult(module="dns", title="DNS records", kind="api")])
    panel.apply_result(
        ModuleResult(
            module="dns",
            title="DNS records",
            kind="api",
            status=ModuleStatus.OK,
            findings=findings,
            raw="raw",
        )
    )

    panel.reset([ModuleResult(module="rdap", title="RDAP", kind="api")])

    assert panel.findings_model.rowCount() == 0
    assert panel.raw_selector.count() == 0
    assert panel.raw_view.toPlainText() == ""
    assert panel.count_label.text() == "No findings yet"


def test_results_panel_reports_filtered_counts(qapp, findings) -> None:
    panel = ResultsPanel()
    panel.reset([ModuleResult(module="dns", title="DNS records", kind="api")])
    panel.apply_result(
        ModuleResult(
            module="dns",
            title="DNS records",
            kind="api",
            status=ModuleStatus.OK,
            findings=findings,
        )
    )

    panel.search.setText("dev.example")
    assert panel.count_label.text() == "1 of 3 findings"
    assert [f.value for f, _ in panel.visible_findings()] == ["dev.example.com"]


def test_results_panel_switches_to_raw_output_for_a_module(qapp, findings) -> None:
    panel = ResultsPanel()
    panel.reset([ModuleResult(module="dns", title="DNS records", kind="api")])
    panel.apply_result(
        ModuleResult(
            module="dns",
            title="DNS records",
            kind="api",
            status=ModuleStatus.OK,
            findings=findings,
            raw="raw dns output",
        )
    )

    panel.show_module_raw("dns")

    assert panel.tabs.currentIndex() == 2
    assert panel.raw_view.toPlainText() == "raw dns output"


# -- personal targets --------------------------------------------------------


def test_target_bar_classifies_people_and_phone_numbers(qapp) -> None:
    bar = TargetBar()

    bar.input.setText("Ada Lovelace")
    assert bar.target.type is TargetType.PERSON

    bar.input.setText("+1 415 555 0100")
    assert bar.target.type is TargetType.PHONE
    assert bar.target.value == "+14155550100"


def test_module_panel_offers_only_person_modules_for_a_name(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("Ada Lovelace"))

    offered = {panel.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(panel.list.count())}
    assert {"links", "records", "wikidata", "sec", "courtlistener"} <= offered
    # Nothing that only makes sense against infrastructure.
    assert not offered & {"dns", "crtsh", "geoip", "whois", "phone"}


def test_module_panel_offers_phone_modules_for_a_number(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("+14155550100"))

    offered = {panel.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(panel.list.count())}
    assert {"phone", "links"} <= offered
    assert "dns" not in offered


def test_module_panel_warns_that_a_target_is_a_person(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("bob@example.com"))

    assert "identifies a person" in panel.summary.text()
    assert "run offline" in panel.summary.text()


def test_module_panel_stays_quiet_for_infrastructure(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("example.com"))

    assert "identifies a person" not in panel.summary.text()


def test_module_panel_tooltip_says_what_leaves_the_machine(qapp) -> None:
    panel = ModulePanel(Settings())
    panel.set_target(parse_target("+14155550100"))

    tooltips = {
        panel.list.item(i).data(Qt.ItemDataRole.UserRole): panel.list.item(i).toolTip()
        for i in range(panel.list.count())
    }
    assert "Runs offline" in tooltips["phone"]
    assert "Runs offline" in tooltips["links"]


def test_results_panel_keeps_the_value_column_usable(qapp) -> None:
    """Long detail strings must not squeeze the column holding the finding."""
    panel = ResultsPanel()
    panel.resize(1100, 600)
    panel.show()
    QApplication.processEvents()
    panel.reset([ModuleResult(module="links", title="Search links", kind="local")])
    panel.apply_result(
        ModuleResult(
            module="links",
            title="Search links",
            kind="local",
            status=ModuleStatus.OK,
            findings=[
                Finding(
                    "search",
                    "DuckDuckGo (digits only)",
                    "https://duckduckgo.com/?q=%22" + "1" * 60 + "%22",
                    "some listings omit the country code entirely, so search both ways",
                )
            ],
        )
    )

    table = panel.findings_table
    widths = [table.columnWidth(c) for c in range(6)]

    assert widths[3] >= 300, f"value column squeezed to {widths[3]}px: {widths}"
    # The value column must also end up the widest of them all.
    assert widths[3] == max(widths)


# -- profile panel -----------------------------------------------------------


def profile_scan(target: str, module: str, findings_list):
    from wosint.core.models import Scan
    from wosint.core.targets import parse_target as _parse

    scan = Scan(target=_parse(target))
    scan.results[module] = ModuleResult(
        module=module, title=module, kind="api", status=ModuleStatus.OK, findings=findings_list
    )
    scan.finished_at = scan.started_at
    return scan


def test_profile_panel_starts_empty(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    assert panel.tree.topLevelItemCount() == 0
    assert "Nothing scanned" in panel.heading.text()


def test_profile_panel_groups_entities_by_type(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan(
            "bob@example.com",
            "gravatar",
            [
                Finding("profile", "Full name", "Jane Doe"),
                Finding("account", "Github", "https://github.com/janedoe"),
            ],
        )
    )

    groups = {
        panel.tree.topLevelItem(i).text(0).split("  (")[0]
        for i in range(panel.tree.topLevelItemCount())
    }
    assert {"Name", "Email address", "Username", "Account"} <= groups


def test_profile_panel_accumulates_across_scans(qapp) -> None:
    """The point of the panel: a second scan adds to the picture."""
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan("bob@example.com", "gravatar", [Finding("profile", "Full name", "Jane Doe")])
    )
    panel.add_scan(profile_scan("janedoe", "github", [Finding("profile", "Location", "Berlin")]))

    assert panel.investigation.scanned == ["bob@example.com", "janedoe"]
    assert "2 scans" in panel.subheading.text()


def test_profile_panel_lists_pivots_and_marks_scanned_ones(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/janedoe")],
        )
    )

    rows = [
        panel.pivot_tree.topLevelItem(i).text(0)
        for i in range(panel.pivot_tree.topLevelItemCount())
    ]
    assert any("janedoe" in row for row in rows)
    reasons = [
        panel.pivot_tree.topLevelItem(i).text(1)
        for i in range(panel.pivot_tree.topLevelItemCount())
    ]
    assert any("already scanned" in reason for reason in reasons)


def test_profile_panel_emits_the_chosen_pivot(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/janedoe")],
        )
    )
    emitted = []
    panel.pivot_requested.connect(emitted.append)

    for i in range(panel.pivot_tree.topLevelItemCount()):
        item = panel.pivot_tree.topLevelItem(i)
        if "janedoe" in item.text(0):
            panel.pivot_tree.setCurrentItem(item)
            break
    panel.follow_button.click()

    assert [p.value for p in emitted] == ["janedoe"]


def test_profile_panel_shows_inferred_entities_as_unconfirmed(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan(
            "beau@example.com",
            "gitlab",
            [Finding("profile", "Name", "Somebody Else", "guessed", inferred=True)],
        )
    )

    for i in range(panel.tree.topLevelItemCount()):
        group = panel.tree.topLevelItem(i)
        if group.text(0).startswith("Name"):
            child = group.child(0)
            assert child.text(2) == "inferred, unconfirmed"
            assert child.font(0).italic()
            assert "may belong to a different person" in child.toolTip(0)
            return
    pytest.fail("no name group rendered")


def test_profile_panel_reset_clears_everything(qapp) -> None:
    from wosint.gui.widgets.profile_panel import ProfilePanel

    panel = ProfilePanel()
    panel.add_scan(
        profile_scan("bob@example.com", "gravatar", [Finding("profile", "Full name", "Jane Doe")])
    )
    panel.reset()

    assert panel.tree.topLevelItemCount() == 0
    assert panel.investigation.entities == {}


# -- explicit target type in the bar -----------------------------------------


def test_target_bar_defaults_to_detecting_the_type(qapp) -> None:
    bar = TargetBar()
    bar.input.setText("Beau")

    assert bar.chosen_type is None
    assert bar.target.type is TargetType.USERNAME
    assert "Read as username" in bar.status.text()


def test_target_bar_honours_a_forced_type(qapp) -> None:
    """A one-word name would otherwise be taken for a handle."""
    bar = TargetBar()
    bar.input.setText("Beau")
    bar.select_type(TargetType.PERSON)

    assert bar.target.type is TargetType.PERSON
    assert bar.target.value == "Beau"
    assert "Treating as person" in bar.status.text()


def test_target_bar_reclassifies_when_the_type_changes(qapp) -> None:
    bar = TargetBar()
    bar.input.setText("5551234")
    assert bar.target.type is TargetType.PHONE

    bar.select_type(TargetType.USERNAME)
    assert bar.target.type is TargetType.USERNAME

    bar.select_type(None)
    assert bar.target.type is TargetType.PHONE


def test_target_bar_explains_an_impossible_override(qapp) -> None:
    bar = TargetBar()
    bar.input.setText("not a domain!!")
    bar.select_type(TargetType.DOMAIN)

    assert bar.target is None
    assert "cannot be read as a domain" in bar.status.text()
    assert not bar.scan_button.isEnabled()


def test_target_bar_offers_person_as_a_choice(qapp) -> None:
    bar = TargetBar()
    offered = {bar.type_selector.itemData(i) for i in range(bar.type_selector.count())}

    assert "person" in offered
    assert "image" in offered
    assert "auto" in offered


# -- photo targets -----------------------------------------------------------


def test_the_photo_row_appears_only_for_an_image(qapp, tmp_path) -> None:
    from PIL import Image as PilImage

    path = tmp_path / "photo.jpg"
    PilImage.new("RGB", (8, 8)).save(path)

    bar = TargetBar()
    bar.show()

    bar.input.setText("example.com")
    assert not bar.photo_row.isVisible()

    bar.input.setText(str(path))
    assert bar.photo_row.isVisible()
    assert bar.target.type is TargetType.IMAGE


def test_the_photo_subject_rides_along_on_the_target(qapp, tmp_path) -> None:
    from PIL import Image as PilImage

    path = tmp_path / "photo.jpg"
    PilImage.new("RGB", (8, 8)).save(path)

    bar = TargetBar()
    bar.input.setText(str(path))
    assert bar.target.hint == "general"

    index = bar.subject_selector.findData("location")
    bar.subject_selector.setCurrentIndex(index)
    assert bar.target.hint == "location"

    index = bar.subject_selector.findData("people")
    bar.subject_selector.setCurrentIndex(index)
    assert bar.target.hint == "people"


def test_the_photo_subject_offers_location_and_people(qapp) -> None:
    bar = TargetBar()
    offered = {bar.subject_selector.itemData(i) for i in range(bar.subject_selector.count())}
    assert offered == {"general", "location", "people"}


def test_a_photo_shows_its_filename_rather_than_its_path(qapp, tmp_path) -> None:
    from PIL import Image as PilImage

    path = tmp_path / "holiday.jpg"
    PilImage.new("RGB", (8, 8)).save(path)

    bar = TargetBar()
    bar.input.setText(str(path))

    assert bar.status.text().endswith("holiday.jpg")


# -- settings dialog ---------------------------------------------------------


def test_the_settings_dialog_offers_a_field_per_keyed_module(qapp) -> None:
    from wosint.gui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())

    assert {"vision", "opensanctions", "opencorporates", "hibp"} <= set(dialog._key_fields)


def test_api_keys_are_masked(qapp) -> None:
    from PySide6.QtWidgets import QLineEdit

    from wosint.gui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())

    assert dialog._key_fields["vision"].echoMode() == QLineEdit.EchoMode.Password


def test_a_key_from_the_environment_is_shown_but_locked(qapp, monkeypatch) -> None:
    from wosint.gui.settings_dialog import SettingsDialog

    monkeypatch.setenv("WOSINT_KEY_OPENSANCTIONS", "from-env")
    settings = Settings.load(Path("/nonexistent/wosint.json"))
    dialog = SettingsDialog(settings)

    assert not dialog._key_fields["opensanctions"].isEnabled()
    assert dialog._key_fields["vision"].isEnabled()


def test_the_dialog_writes_its_edits_back(qapp, monkeypatch) -> None:
    from wosint.gui.settings_dialog import SettingsDialog

    monkeypatch.delenv("WOSINT_KEY_VISION", raising=False)
    settings = Settings()
    dialog = SettingsDialog(settings)

    dialog._key_fields["vision"].setText("a-key")
    dialog.module_timeout.setValue(33.0)
    dialog.max_concurrency.setValue(2)
    dialog.phone_region.setText("gb")
    dialog.contact_email.setText("me@example.com")
    dialog.vision_model.setText("gemini-3.1-flash-preview")
    dialog._module_boxes["wayback"].setChecked(False)
    dialog.apply_to(settings)

    assert settings.api_key("vision") == "a-key"
    assert settings.module_timeout == 33.0
    assert settings.max_concurrency == 2
    assert settings.phone_region == "GB"  # normalised for libphonenumber
    assert settings.contact_email == "me@example.com"
    assert settings.vision_model == "gemini-3.1-flash-preview"
    assert settings.disabled_modules == ["wayback"]


def test_the_dialog_leaves_an_environment_key_alone(qapp, monkeypatch) -> None:
    from wosint.gui.settings_dialog import SettingsDialog

    monkeypatch.setenv("WOSINT_KEY_HIBP", "from-env")
    settings = Settings.load(Path("/nonexistent/wosint.json"))
    dialog = SettingsDialog(settings)
    dialog.apply_to(settings)

    assert settings.api_key("hibp") == "from-env"


def test_the_dialog_lists_every_module_for_disabling(qapp) -> None:
    from wosint.core.registry import all_modules
    from wosint.gui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())

    assert set(dialog._module_boxes) == {m.name for m in all_modules()}


def test_disabled_modules_start_unticked(qapp) -> None:
    from wosint.gui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings(disabled_modules=["dns"]))

    assert not dialog._module_boxes["dns"].isChecked()
    assert dialog._module_boxes["rdap"].isChecked()


def test_the_main_window_has_a_settings_menu(qapp) -> None:
    from wosint.gui.main_window import MainWindow

    window = MainWindow(Settings())
    menus = {action.text() for action in window.menuBar().actions()}

    assert "&Settings" in menus
    window.close()
