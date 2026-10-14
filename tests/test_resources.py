"""Packaged resources: Semgrep rules, known-servers list, stylesheet (Phase 12, AR-150 to AR-158).

Real Semgrep runs (Zero-Execution: the benchmark files are only read, never executed) from three
working directories prove that resolution is independent of the cwd. Installation contexts
(wheel, hidden directory names) are covered by the manual wheel check documented in
docs/ARCHITECTURE.md; here the package data configuration is checked statically."""

import fnmatch
import json
import os
import re
import tomllib
from pathlib import Path

import pytest

import mcpthreat_scan.analyzers.semgrep as semgrep_module
import mcpthreat_scan.analyzers.typosquat as typosquat_module
from mcpthreat_scan.analyzers.semgrep import DEFAULT_RULES_DIR, SemgrepRunnerError, run_semgrep_rules

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "mcpthreat_scan"
RESOURCES = PACKAGE / "resources"
BENCHMARK_VULNERABLE = ROOT / "benchmark" / "vulnerable"

RULE_FILES = [
    "capability_mismatch.yaml",
    "command_injection.yaml",
    "command_injection_node.yaml",
    "hardcoded_secret.yaml",
    "hardcoded_secret_node.yaml",
    "header_leak.yaml",
    "header_leak_node.yaml",
    "missing_audit.yaml",
    "tool_poisoning.yaml",
    "tool_poisoning_node.yaml",
    "tool_poisoning_output.yaml",
    "unscoped_environ.yaml",
    "unscoped_environ_node.yaml",
]


def _normalized(findings):
    # check_id prefix is derived by Semgrep from the rules directory path, so compare the last segment
    return sorted(
        (f["file"], f["line"], f["rule_id"].rsplit(".", 1)[-1], f["category"], f["severity"], f["message"])
        for f in findings
    )


# --- rules: location and content ---------------------------------------------------------------


def test_default_rules_dir_is_absolute_and_inside_the_package_resources():
    assert DEFAULT_RULES_DIR.is_absolute()
    assert DEFAULT_RULES_DIR == RESOURCES / "rules"
    assert semgrep_module.DEFAULT_RULES_DIR is DEFAULT_RULES_DIR


def test_packaged_rules_are_exactly_the_thirteen_expected_yaml_files():
    assert sorted(p.name for p in DEFAULT_RULES_DIR.glob("*.yaml")) == RULE_FILES



def test_rule_id_contract_suffixes_used_by_the_pipeline_exist_in_the_packaged_rules():
    ids = set()
    for path in DEFAULT_RULES_DIR.glob("*.yaml"):
        ids.update(re.findall(r"^\s*-\s*id:\s*(\S+)\s*$", path.read_text(encoding="utf-8"), flags=re.M))

    assert {
        "capability-mismatch-network-candidate",
        "capability-mismatch-email-candidate",
        "tool-poisoning-docstring-candidate",
        "tool-poisoning-output-candidate",
        "command-injection-node",
        "unscoped-environ-node",
        "hardcoded-secret-node",
        "header-leak-node",
        "tool-poisoning-description-node-candidate",
        "tool-poisoning-output-node-candidate",
    } <= ids
    assert len(ids) == 15


# --- rules: resolution independent of the working directory --------------------------------


def test_scan_findings_are_identical_from_repo_root_subfolder_and_foreign_directory(tmp_path, monkeypatch):
    target = str(BENCHMARK_VULNERABLE)
    results = {}
    for label, cwd in {"repo": ROOT, "subfolder": ROOT / "benchmark", "foreign": tmp_path}.items():
        monkeypatch.chdir(cwd)
        results[label] = _normalized(run_semgrep_rules(target))

    assert len(results["repo"]) > 0
    assert results["subfolder"] == results["repo"]
    assert results["foreign"] == results["repo"]



def test_explicit_rules_dir_takes_precedence_over_the_packaged_rules(tmp_path):
    rules = tmp_path / "custom_rules"
    rules.mkdir()
    (rules / "custom.yaml").write_text(
        "rules:\n"
        "  - id: custom-marker\n"
        "    languages: [python]\n"
        "    severity: WARNING\n"
        "    message: custom rule hit\n"
        "    metadata:\n"
        "      category: Custom\n"
        "    pattern: marker_call(...)\n",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.py"
    sample.write_text("marker_call(1)\n", encoding="utf-8")

    findings = run_semgrep_rules(sample, rules_dir=rules)

    assert [(f["category"], f["rule_id"].rsplit(".", 1)[-1]) for f in findings] == [("Custom", "custom-marker")]


def test_missing_default_rules_dir_raises_a_readable_error(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_module, "DEFAULT_RULES_DIR", tmp_path / "gone")

    with pytest.raises(SemgrepRunnerError, match="Rules directory not found"):
        run_semgrep_rules(tmp_path)


# --- known_mcp_servers.json ----------------------------------------------------------------


def test_known_servers_default_path_is_the_packaged_resource():
    assert typosquat_module.DEFAULT_KNOWN_SERVERS_PATH == RESOURCES / "known_mcp_servers.json"
    assert typosquat_module.DEFAULT_KNOWN_SERVERS_PATH.is_absolute()



def test_known_servers_load_is_identical_from_repo_root_and_foreign_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    from_repo = typosquat_module.load_known_servers()
    monkeypatch.chdir(tmp_path)
    from_foreign = typosquat_module.load_known_servers()

    assert from_foreign == from_repo
    assert len(from_repo) == 417
    assert from_repo == json.loads((RESOURCES / "known_mcp_servers.json").read_text(encoding="utf-8"))["servers"]


# --- stylesheet and package data -----------------------------------------------------------


def test_stylesheet_is_found_next_to_the_target_app_from_a_foreign_directory(tmp_path, monkeypatch):
    from mcpthreat_scan.tui.app import MCPScannerApp

    monkeypatch.chdir(tmp_path)

    assert [Path(p) for p in MCPScannerApp().css_path] == [PACKAGE / "tui" / "app.tcss"]
    assert (PACKAGE / "tui" / "app.tcss").is_file()


def test_package_data_covers_every_non_python_file_in_the_package():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = config["tool"]["setuptools"]["package-data"]["mcpthreat_scan"]

    uncovered = []
    for path in sorted(PACKAGE.rglob("*")):
        if not path.is_file() or path.suffix in {".py", ".pyc"} or path.name == ".gitkeep":
            continue
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(PACKAGE).as_posix()
        if not any(fnmatch.fnmatch(relative, pattern) for pattern in patterns):
            uncovered.append(relative)

    assert uncovered == []


def test_package_data_lists_the_three_resource_groups():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = config["tool"]["setuptools"]["package-data"]["mcpthreat_scan"]

    assert sorted(patterns) == ["resources/known_mcp_servers.json", "resources/rules/*.yaml", "tui/app.tcss"]


# --- no hard-coded repository or developer paths (AR-157) ----------------------------------

_FORBIDDEN_FRAGMENTS = ["c:\\users", "c:/users", "/home/", "/users/", "thalf", "documents\\mcp", "documents/mcp"]


def test_product_code_has_no_absolute_developer_paths():
    bad = []
    for path in sorted(PACKAGE.rglob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        for fragment in _FORBIDDEN_FRAGMENTS:
            if fragment in text:
                bad.append(f"{path.relative_to(ROOT).as_posix()}: {fragment}")

    assert bad == []


def test_product_code_has_no_cwd_relative_resource_paths():
    # Path("rules"), "rules/...", "known_mcp_servers.json" as bare relative literals would depend on the cwd
    pattern = re.compile(r"""Path\(\s*["'](rules|resources|known_mcp_servers\.json)["']""")
    bad = []
    for path in sorted(PACKAGE.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.search(line):
                bad.append(f"{path.relative_to(ROOT).as_posix()}:{number}")

    assert bad == []


def test_resource_paths_in_product_code_are_derived_from_module_files():
    assert "__file__" in Path(semgrep_module.__file__).read_text(encoding="utf-8")
    assert "__file__" in Path(typosquat_module.__file__).read_text(encoding="utf-8")
    assert os.path.isabs(semgrep_module.__file__)
