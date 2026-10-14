"""Tests for P5-2: unified report building and rendering (text/JSON).

Covers merging Semgrep/OSV findings, summary scoring, and output formats."""

import json

from mcpthreat_scan.analyzers.ai_review import AIReviewError
from mcpthreat_scan.core.exceptions import ReportError
from mcpthreat_scan.core.models import exceeds_severity_threshold
from mcpthreat_scan.core.orchestrator import run_diff, run_scan
from mcpthreat_scan.reporting.json import render_json
from mcpthreat_scan.reporting.sarif import render_sarif
from mcpthreat_scan.reporting.text import render_text

RUGPULL_DIR = "benchmark/rugpull"


def test_build_report_on_single_vulnerable_file():
    report = run_scan("benchmark/vulnerable/command_injection.py")

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["category"] == "Command Injection"
    assert finding["line"] == 9
    assert finding["severity"] == "ERROR"

    assert report["summary"] == {
        "categories_checked": 9,
        "categories_without_finding": 8,
        "categories_with_finding": ["Command Injection"],
    }


def test_build_report_on_clean_file_has_full_score():
    report = run_scan("benchmark/clean/example_server_weather.py")

    assert report["findings"] == []
    assert report["summary"] == {
        "categories_checked": 9,
        "categories_without_finding": 9,
        "categories_with_finding": [],
    }


def test_build_report_on_whole_benchmark_matches_known_categories():
    report = run_scan("benchmark/")

    assert report["summary"]["categories_with_finding"] == [
        "Capability Mismatch",
        "Command Injection",
        "Hardcoded Secret",
        "Header Leak",
        "Missing Audit Logging",
        "Supply Chain",
        "Tool Poisoning",
        "Typosquatting / Shadow-Server",
        "Unscoped Environment Access",
    ]
    assert report["summary"]["categories_without_finding"] == 0


def test_build_report_runs_dependency_check_when_requirements_txt_present(
    tmp_path, monkeypatch
):
    (tmp_path / "main.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("some-package==1.0.0\n", encoding="utf-8")

    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.check_requirements_file",
        lambda path: [
            {
                "name": "some-package",
                "version": "1.0.0",
                "vulnerabilities": [{"id": "OSV-FAKE-1234"}],
            }
        ],
    )

    report = run_scan(tmp_path)

    supply_chain_findings = [f for f in report["findings"] if f["category"] == "Supply Chain"]
    assert len(supply_chain_findings) == 1
    assert supply_chain_findings[0]["line"] is None
    assert supply_chain_findings[0]["severity"] == "ERROR"
    assert "some-package==1.0.0" in supply_chain_findings[0]["message"]
    assert "OSV-FAKE-1234" in supply_chain_findings[0]["message"]
    assert report["summary"]["categories_with_finding"] == ["Supply Chain"]


def test_build_report_raises_report_error_when_semgrep_target_missing():
    try:
        run_scan("does/not/exist")
        assert False, "expected a ReportError"
    except ReportError:
        pass


def test_render_json_produces_valid_parseable_json():
    report = run_scan("benchmark/vulnerable/command_injection.py")

    parsed = json.loads(render_json(report))

    assert parsed == report


def test_render_text_lists_finding_and_summary():
    report = run_scan("benchmark/vulnerable/command_injection.py")

    text = render_text(report)

    assert "command_injection.py" in text
    assert "Line 9" in text
    assert "[Command Injection]" in text
    assert "8 of 9 OWASP MCP categories without findings" in text


TOOL_POISONING_CANDIDATE_FILE = "benchmark/vulnerable/tool_poisoning_docstring.py"


def test_build_report_without_ai_review_flag_leaves_candidate_unconfirmed():
    """Default behaviour (no ai_review=True) must stay exactly as before P8-4."""
    report = run_scan(TOOL_POISONING_CANDIDATE_FILE)

    finding = report["findings"][0]
    assert finding["severity"] == "WARNING"
    assert "candidate, NOT an automatic error" in finding["message"]


def test_build_report_with_ai_review_confirms_hidden_instruction(monkeypatch):
    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.review_candidate",
        lambda text: {"suspicious": True, "reasoning": "Contains a hidden instruction.", "confidence": 0.95},
    )

    report = run_scan(TOOL_POISONING_CANDIDATE_FILE, ai_review=True)

    finding = report["findings"][0]
    assert finding["category"] == "Tool Poisoning"
    assert finding["severity"] == "ERROR"
    assert "CONFIRMED" in finding["message"]
    assert "0.95" in finding["message"]


def test_build_report_with_ai_review_clears_benign_control_case(monkeypatch):
    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.review_candidate",
        lambda text: {"suspicious": False, "reasoning": "Perfectly normal API documentation.", "confidence": 0.9},
    )

    report = run_scan("benchmark/clean/example_server_appointments.py", ai_review=True)

    finding = report["findings"][0]
    assert finding["severity"] == "INFO"
    assert "no tool poisoning detected" in finding["message"]


def test_build_report_with_ai_review_missing_api_key_does_not_abort_scan(monkeypatch):
    def raise_missing_key(text):
        raise AIReviewError("OPENAI_API_KEY is not set - the layer-2 review cannot be performed.")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.review_candidate", raise_missing_key)

    report = run_scan(TOOL_POISONING_CANDIDATE_FILE, ai_review=True)

    finding = report["findings"][0]
    # Still just an unconfirmed candidate - NOT an error, NOT a crash.
    assert finding["severity"] == "WARNING"
    assert "Automatic layer-2 review not possible" in finding["message"]
    assert "OPENAI_API_KEY" in finding["message"]


def test_build_report_with_ai_review_does_not_touch_non_tool_poisoning_findings(monkeypatch):
    def fail_if_called(text):
        raise AssertionError("review_candidate must not run for non-Tool-Poisoning findings")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.review_candidate", fail_if_called)

    report = run_scan("benchmark/vulnerable/command_injection.py", ai_review=True)

    assert report["findings"][0]["category"] == "Command Injection"
    assert report["findings"][0]["severity"] == "ERROR"


def test_render_text_on_clean_report_says_keine_funde():
    report = run_scan("benchmark/clean/example_server_weather.py")

    text = render_text(report)

    assert "No findings." in text
    assert "9 of 9 OWASP MCP categories without findings" in text


# ============================================================================
# P8-3: run_diff() - wires scanner/rugpull_diff.py (P4-2) into the
# same unified report shape as run_scan() above. Reuses the exact same
# two DoD fixture pairs already proven correct at the rugpull_diff.py level
# in tests/test_rugpull_diff.py - this file only checks that the REPORT
# WRAPPING (category/file/line/severity/message, summary score) is correct,
# not the underlying diff logic itself again.
# ============================================================================


def test_diff_report_on_hidden_bcc_pair_reports_error_severity():
    report = run_diff(
        f"{RUGPULL_DIR}/example_email_bcc_v1.py", f"{RUGPULL_DIR}/example_email_bcc_v2.py"
    )

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["category"] == "Tool Poisoning"
    assert finding["line"] is None
    assert finding["severity"] == "ERROR"
    assert "example_email_bcc_v2.py" in finding["file"]
    assert report["summary"]["categories_with_finding"] == ["Tool Poisoning"]


def test_diff_report_on_schema_change_pair_reports_two_warning_findings():
    report = run_diff(
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
        f"{RUGPULL_DIR}/example_search_schema_v2.py",
    )

    changes_by_message = [f["message"] for f in report["findings"]]
    assert len(report["findings"]) == 2
    assert all(f["severity"] == "WARNING" for f in report["findings"])
    assert any("include_private" in message for message in changes_by_message)
    assert any("Docstring" in message for message in changes_by_message)


def test_diff_report_on_identical_files_has_no_findings():
    report = run_diff(
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
    )

    assert report["findings"] == []
    assert report["summary"]["categories_without_finding"] == 9


def test_diff_report_renders_as_text_without_misleading_paket_label():
    report = run_diff(
        f"{RUGPULL_DIR}/example_email_bcc_v1.py", f"{RUGPULL_DIR}/example_email_bcc_v2.py"
    )

    text = render_text(report)

    assert "Package" not in text
    assert "no line reference" in text


def test_build_report_suppresses_finding_listed_in_ignore_file(tmp_path):
    baseline_report = run_scan("benchmark/vulnerable/command_injection.py")
    finding = baseline_report["findings"][0]

    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text(f"{finding['file']}:{finding['category']}\n", encoding="utf-8")

    report = run_scan("benchmark/vulnerable/command_injection.py", ignore_file=ignore_file)

    assert report["findings"] == []
    assert report["summary"]["suppressed_count"] == 1
    assert report["summary"]["categories_with_finding"] == []


def test_build_report_without_ignore_file_leaves_summary_unchanged(tmp_path):
    missing_ignore_file = tmp_path / ".mcpscannerignore"

    report = run_scan(
        "benchmark/vulnerable/command_injection.py", ignore_file=missing_ignore_file
    )

    assert "suppressed_count" not in report["summary"]


def test_exceeds_severity_threshold_true_when_above_threshold():
    findings = [{"severity": "ERROR"}]

    assert exceeds_severity_threshold(findings, "WARNING") is True


def test_exceeds_severity_threshold_true_on_exact_match():
    findings = [{"severity": "WARNING"}]

    assert exceeds_severity_threshold(findings, "WARNING") is True


def test_exceeds_severity_threshold_false_when_below_threshold():
    findings = [{"severity": "INFO"}]

    assert exceeds_severity_threshold(findings, "ERROR") is False


def test_exceeds_severity_threshold_false_on_empty_findings():
    assert exceeds_severity_threshold([], "INFO") is False


def test_exceeds_severity_threshold_true_if_any_finding_qualifies():
    findings = [{"severity": "INFO"}, {"severity": "ERROR"}, {"severity": "WARNING"}]

    assert exceeds_severity_threshold(findings, "ERROR") is True


# ============================================================================
# P10-4: dependency-file detection (requirements.txt > pyproject.toml (PEP
# 621) > poetry.lock), all mocked - the underlying check functions are
# already proven live against OSV in tests/test_dependency_check.py.
# ============================================================================


def test_build_report_runs_pyproject_check_when_pep621_dependencies_present(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["some-package==1.0.0"]\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.check_pyproject_dependencies",
        lambda path: [
            {"name": "some-package", "version": "1.0.0", "vulnerabilities": [{"id": "OSV-FAKE-1234"}]}
        ],
    )

    report = run_scan(tmp_path)

    supply_chain_findings = [f for f in report["findings"] if f["category"] == "Supply Chain"]
    assert len(supply_chain_findings) == 1
    assert "pyproject.toml" in supply_chain_findings[0]["file"]
    assert "some-package==1.0.0" in supply_chain_findings[0]["message"]


def test_build_report_runs_poetry_lock_check_when_poetry_lock_present(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "some-package"\nversion = "1.0.0"\n', encoding="utf-8"
    )

    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.check_poetry_lock_dependencies",
        lambda path: [
            {"name": "some-package", "version": "1.0.0", "vulnerabilities": [{"id": "OSV-FAKE-1234"}]}
        ],
    )

    report = run_scan(tmp_path)

    supply_chain_findings = [f for f in report["findings"] if f["category"] == "Supply Chain"]
    assert len(supply_chain_findings) == 1
    assert "poetry.lock" in supply_chain_findings[0]["file"]


def test_build_report_prefers_requirements_txt_over_pyproject_toml(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("some-package==1.0.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = ["other-package==2.0.0"]\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.check_requirements_file",
        lambda path: [
            {"name": "some-package", "version": "1.0.0", "vulnerabilities": [{"id": "OSV-FAKE-1234"}]}
        ],
    )

    def fail_if_called(path):
        raise AssertionError("check_pyproject_dependencies must not run when requirements.txt is present")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.check_pyproject_dependencies", fail_if_called)

    report = run_scan(tmp_path)

    supply_chain_findings = [f for f in report["findings"] if f["category"] == "Supply Chain"]
    assert len(supply_chain_findings) == 1
    assert "requirements.txt" in supply_chain_findings[0]["file"]


def test_build_report_skips_dependency_check_for_legacy_poetry_style_without_lock(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "x"\nversion = "0.1.0"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.10"\nurllib3 = "1.26.4"\n',
        encoding="utf-8",
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("no dependency check must run for legacy Poetry style without a lock file")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.check_pyproject_dependencies", fail_if_called)
    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.check_poetry_lock_dependencies", fail_if_called)

    report = run_scan(tmp_path)

    assert [f for f in report["findings"] if f["category"] == "Supply Chain"] == []


# ============================================================================
# P10-3: render_sarif() - third output format (SARIF 2.1.0) alongside
# render_json()/render_text(), same report shape as input.
# ============================================================================


def test_render_sarif_has_required_top_level_fields():
    report = run_scan("benchmark/vulnerable/command_injection.py")

    parsed = json.loads(render_sarif(report))

    assert parsed["$schema"].startswith("https://")
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"]) == 1
    run = parsed["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpthreat-scan"
    assert len(run["tool"]["driver"]["rules"]) == 9


def test_render_sarif_maps_finding_to_result_with_location():
    report = run_scan("benchmark/vulnerable/command_injection.py")
    finding = report["findings"][0]

    parsed = json.loads(render_sarif(report))
    result = parsed["runs"][0]["results"][0]

    assert result["ruleId"] == "command-injection"
    assert result["level"] == "error"
    assert result["message"]["text"] == finding["message"]
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "benchmark/vulnerable/command_injection.py"
    assert location["region"]["startLine"] == finding["line"]


def test_render_sarif_maps_all_three_severities_to_sarif_levels():
    report = {
        "target": "x",
        "findings": [
            {"category": "Header Leak", "file": "a.py", "line": 1, "severity": "ERROR", "message": "m1"},
            {"category": "Tool Poisoning", "file": "a.py", "line": 2, "severity": "WARNING", "message": "m2"},
            {"category": "Missing Audit Logging", "file": "a.py", "line": None, "severity": "INFO", "message": "m3"},
        ],
        "summary": {},
    }

    parsed = json.loads(render_sarif(report))
    levels_by_message = {r["message"]["text"]: r["level"] for r in parsed["runs"][0]["results"]}

    assert levels_by_message["m1"] == "error"
    assert levels_by_message["m2"] == "warning"
    assert levels_by_message["m3"] == "note"


def test_render_sarif_omits_region_when_line_is_none():
    report = {
        "target": "x",
        "findings": [
            {"category": "Supply Chain", "file": "requirements.txt", "line": None, "severity": "ERROR", "message": "m"},
        ],
        "summary": {},
    }

    parsed = json.loads(render_sarif(report))
    location = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert "region" not in location
    assert location["artifactLocation"]["uri"] == "requirements.txt"


def test_render_sarif_converts_windows_path_separators_to_forward_slashes():
    report = {
        "target": "x",
        "findings": [
            {"category": "Header Leak", "file": r"benchmark\vulnerable\x.py", "line": 3, "severity": "ERROR", "message": "m"},
        ],
        "summary": {},
    }

    parsed = json.loads(render_sarif(report))
    uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    assert uri == "benchmark/vulnerable/x.py"
    assert "\\" not in uri


def test_render_sarif_result_rule_ids_all_exist_in_rule_catalog():
    report = run_scan("benchmark/")

    parsed = json.loads(render_sarif(report))
    catalog_ids = {rule["id"] for rule in parsed["runs"][0]["tool"]["driver"]["rules"]}
    result_ids = {r["ruleId"] for r in parsed["runs"][0]["results"]}

    assert result_ids <= catalog_ids


def test_render_sarif_result_count_matches_findings_count():
    report = run_scan("benchmark/")

    parsed = json.loads(render_sarif(report))

    assert len(parsed["runs"][0]["results"]) == len(report["findings"])
