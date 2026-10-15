"""Report enrichment and version comparison (TUI redesign): rule id and evidence on every finding,
progress phases, remediation text, source-file count, and the new/resolved findings comparison.

Real scans of the benchmark files (Semgrep); nothing is mocked."""

import json
import shutil
from pathlib import Path

import pytest

from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.core.models import REMEDIATION_BY_CATEGORY, VULNERABILITY_CATEGORIES, recommendation_for
from mcpthreat_scan.core.orchestrator import (
    count_source_files,
    run_diff,
    run_scan,
    run_version_comparison,
)
from mcpthreat_scan.reporting.json import render_json

BENCH = Path("benchmark")


def test_every_finding_has_a_rule_id_without_the_semgrep_path_prefix(tmp_path):
    report = run_scan(BENCH / "vulnerable" / "command_injection.py", ignore_file=tmp_path / "none")

    assert report["findings"]
    for finding in report["findings"]:
        assert finding["rule_id"] and "." not in finding["rule_id"]
        assert "\\" not in finding["rule_id"] and "/" not in finding["rule_id"]


def test_evidence_is_the_flagged_source_line(tmp_path):
    source = BENCH / "vulnerable" / "command_injection.py"
    report = run_scan(source, ignore_file=tmp_path / "none")
    lines = source.read_text(encoding="utf-8").splitlines()

    finding = next(f for f in report["findings"] if f["category"] == "Command Injection")

    assert finding["evidence"] == " ".join(lines[finding["line"] - 1].split())


def test_tool_poisoning_candidate_evidence_is_the_flagged_description(tmp_path):
    report = run_scan(BENCH / "vulnerable" / "tool_poisoning_docstring.py", ignore_file=tmp_path / "none")

    finding = next(f for f in report["findings"] if f["category"] == "Tool Poisoning")

    assert finding["evidence"]
    assert not finding["evidence"].startswith("def ")


def test_hardcoded_secret_findings_never_carry_the_source_line(tmp_path):
    source = BENCH / "vulnerable" / "hardcoded_api_key.py"
    report = run_scan(source, ignore_file=tmp_path / "none")

    secrets = [f for f in report["findings"] if f["category"] == "Hardcoded Secret"]

    assert secrets and all(f["evidence"] is None for f in secrets)
    # the secret literal itself must not appear anywhere in the rendered report
    literal = next(
        line.split('"')[1]
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("api_key = ")
    )
    assert literal not in render_json(report)


def test_findings_without_a_line_have_no_evidence_but_keep_the_keys():
    report = run_diff(BENCH / "rugpull" / "example_email_bcc_v1.py", BENCH / "rugpull" / "example_email_bcc_v2.py")

    assert report["findings"]
    assert all(f["line"] is None and f["evidence"] is None for f in report["findings"])
    assert all(f["rule_id"].startswith("rugpull-") for f in report["findings"])


def test_progress_reports_the_phases_in_order(tmp_path):
    phases = []

    run_scan(BENCH / "clean" / "example_server_help.py", ignore_file=tmp_path / "none", progress=phases.append)

    assert phases[0] == "Static rules (Semgrep)"
    assert phases[-1] == "Collecting evidence"
    assert phases.index("Dependency check") < phases.index("Manifest check") < phases.index("Applying ignore rules")


def test_every_category_has_a_remediation_and_special_rows_are_honest():
    assert set(REMEDIATION_BY_CATEGORY) == set(VULNERABILITY_CATEGORIES)
    assert all(REMEDIATION_BY_CATEGORY.values())
    assert "Not a vulnerability" in recommendation_for({"category": "Scan Coverage", "severity": "INFO"})
    assert "osv-scanner" in recommendation_for({"category": "Supply Chain", "severity": "INFO"})
    assert recommendation_for({"category": "Supply Chain", "severity": "ERROR"}) == REMEDIATION_BY_CATEGORY["Supply Chain"]
    assert recommendation_for({"category": "Something New", "severity": "ERROR"})


def test_count_source_files_counts_py_and_ts_js_without_third_party_folders(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("export {}\n", encoding="utf-8")
    (tmp_path / "types.d.ts").write_text("export {}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("1\n", encoding="utf-8")

    assert count_source_files(tmp_path) == 2
    assert count_source_files(tmp_path / "a.py") == 1


def _folder_with(tmp_path, name, source):
    folder = tmp_path / name
    folder.mkdir()
    shutil.copy(source, folder / "server.py")
    return folder


def test_comparison_of_folders_reports_new_findings_and_modified_files(tmp_path):
    before = _folder_with(tmp_path, "v1", BENCH / "clean" / "example_server_help.py")
    after = _folder_with(tmp_path, "v2", BENCH / "vulnerable" / "command_injection.py")
    (after / "extra.py").write_text("x = 1\n", encoding="utf-8")
    phases = []

    result = run_version_comparison(before, after, ignore_file=tmp_path / "none", progress=phases.append)

    assert result["mode"] == "folders"
    assert result["files"] == {"added": ["extra.py"], "removed": [], "modified": ["server.py"]}
    assert "Command Injection" in {f["category"] for f in result["new_findings"]}
    assert result["resolved_findings"] == []
    assert phases[0] == "Comparing files" and phases[-1] == "Comparing findings"


def test_comparison_in_the_other_direction_reports_the_same_findings_as_resolved(tmp_path):
    clean = _folder_with(tmp_path, "clean", BENCH / "clean" / "example_server_help.py")
    bad = _folder_with(tmp_path, "bad", BENCH / "vulnerable" / "command_injection.py")

    forward = run_version_comparison(clean, bad, ignore_file=tmp_path / "none")
    backward = run_version_comparison(bad, clean, ignore_file=tmp_path / "none")

    assert {(f["category"], f["rule_id"]) for f in forward["new_findings"]} == {
        (f["category"], f["rule_id"]) for f in backward["resolved_findings"]
    }
    assert backward["new_findings"] == []


def test_comparison_of_identical_folders_has_no_changes(tmp_path):
    one = _folder_with(tmp_path, "one", BENCH / "vulnerable" / "command_injection.py")
    two = _folder_with(tmp_path, "two", BENCH / "vulnerable" / "command_injection.py")

    result = run_version_comparison(one, two, ignore_file=tmp_path / "none")

    assert result["files"] == {"added": [], "removed": [], "modified": []}
    assert result["new_findings"] == [] and result["resolved_findings"] == []
    assert result["unchanged_count"] > 0


def test_comparison_of_two_files_includes_the_tool_definition_changes(tmp_path):
    result = run_version_comparison(
        BENCH / "rugpull" / "example_email_bcc_v1.py",
        BENCH / "rugpull" / "example_email_bcc_v2.py",
        ignore_file=tmp_path / "none",
    )

    assert result["mode"] == "files"
    assert result["files"]["modified"] == ["example_email_bcc_v2.py"]
    assert result["tool_changes"]
    assert {f["category"] for f in result["tool_changes"]} == {"Tool Poisoning"}


def test_comparison_lists_tools_of_added_and_removed_files(tmp_path):
    before = tmp_path / "v1"
    after = tmp_path / "v2"
    before.mkdir()
    after.mkdir()
    shutil.copy(BENCH / "rugpull" / "example_email_bcc_v1.py", after / "mail.py")

    result = run_version_comparison(before, after, ignore_file=tmp_path / "none")

    assert result["files"]["added"] == ["mail.py"]
    assert any(f["rule_id"] == "rugpull-tool-added" for f in result["tool_changes"])


@pytest.mark.parametrize("missing", ["before", "after"])
def test_comparison_rejects_missing_paths_and_file_folder_mixes(tmp_path, missing):
    real = tmp_path / "real"
    real.mkdir()
    gone = tmp_path / "gone"
    pair = (gone, real) if missing == "before" else (real, gone)

    with pytest.raises(ReportError, match="not found"):
        run_version_comparison(*pair)
    with pytest.raises(ReportError, match="file with a folder"):
        run_version_comparison(BENCH / "clean" / "example_server_help.py", real)


def test_report_json_stays_valid_and_machine_readable_with_the_new_fields(tmp_path):
    report = run_scan(BENCH / "vulnerable" / "command_injection.py", ignore_file=tmp_path / "none")

    parsed = json.loads(render_json(report))

    assert all({"rule_id", "evidence"} <= set(f) for f in parsed["findings"])
