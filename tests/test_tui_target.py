"""Target TUI package (AR-137 to AR-146); the legacy `tui.*` wrappers were removed in Phase 14.

Static checks plus a stylesheet lookup from a foreign working directory; the interactive
behaviour itself is covered by tests/test_tui.py (which runs against the target classes)."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_TUI = ROOT / "src" / "mcpthreat_scan" / "tui"


def test_stylesheet_is_found_next_to_the_target_app_from_any_working_directory(tmp_path, monkeypatch):
    from mcpthreat_scan.tui.app import MCPScannerApp

    monkeypatch.chdir(tmp_path)

    css_paths = [Path(p) for p in MCPScannerApp().css_path]

    assert css_paths == [TARGET_TUI / "app.tcss"]
    assert css_paths[0].is_file()


def test_stylesheet_copy_is_active_package_data():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "tui/app.tcss" in config["tool"]["setuptools"]["package-data"]["mcpthreat_scan"]


def test_every_target_screen_package_has_an_init_module_for_package_discovery():
    for directory in (TARGET_TUI, TARGET_TUI / "screens"):
        assert (directory / "__init__.py").is_file()
