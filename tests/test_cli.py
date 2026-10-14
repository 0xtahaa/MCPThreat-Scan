"""Tests for P5-1/P5-2: CLI scan subcommand, report formats, and argument handling."""

import json

from mcpthreat_scan.cli.main import main


def test_scan_default_format_is_readable_text(capsys):
    exit_code = main(["scan", "benchmark/vulnerable/command_injection.py"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "command_injection.py" in output
    assert "[Command Injection]" in output
    assert "Line 9" in output
    assert "Summary:" in output


def test_scan_format_json_is_valid_json(capsys):
    exit_code = main(
        ["scan", "benchmark/vulnerable/command_injection.py", "--format", "json"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    assert parsed["findings"][0]["category"] == "Command Injection"
    assert parsed["summary"]["categories_without_finding"] == 8


def test_scan_clean_file_reports_no_findings(capsys):
    exit_code = main(["scan", "benchmark/clean/example_server_weather.py"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No findings." in output
    assert "9 of 9" in output


def test_scan_missing_path_returns_error_exit_code(capsys):
    exit_code = main(["scan", "does/not/exist"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "not found" in captured.err


def test_scan_runs_dependency_check_when_requirements_txt_present(
    tmp_path, monkeypatch, capsys
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

    exit_code = main(["scan", str(tmp_path), "--format", "json"])
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    supply_chain_findings = [f for f in parsed["findings"] if f["category"] == "Supply Chain"]
    assert len(supply_chain_findings) == 1
    assert "some-package==1.0.0" in supply_chain_findings[0]["message"]
    assert "OSV-FAKE-1234" in supply_chain_findings[0]["message"]


def test_scan_with_ai_review_flag_confirms_hidden_instruction(capsys, monkeypatch):
    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.review_candidate",
        lambda text: {"suspicious": True, "reasoning": "Hidden instruction.", "confidence": 0.95},
    )

    exit_code = main(
        ["scan", "benchmark/vulnerable/tool_poisoning_docstring.py", "--ai-review"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "CONFIRMED" in output
    assert "[Tool Poisoning]" in output


def test_scan_without_ai_review_flag_keeps_plain_candidate_label(capsys):
    exit_code = main(["scan", "benchmark/vulnerable/tool_poisoning_docstring.py"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "candidate, NOT an automatic error" in output


def test_scan_with_ai_review_handles_real_umlauts_in_llm_answer(capsys, monkeypatch):
    """Verify UTF-8 output when LLM answer contains non-ASCII characters."""
    monkeypatch.setattr(
        "mcpthreat_scan.core.orchestrator.review_candidate",
        lambda text: {
            "suspicious": True,
            "reasoning": "The docstring contains a hidden instruction (naïve “quotes”).",
            "confidence": 0.95,
        },
    )

    exit_code = main(
        [
            "scan",
            "benchmark/vulnerable/tool_poisoning_docstring.py",
            "--ai-review",
            "--format",
            "json",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    assert "naïve" in parsed["findings"][0]["message"]


def test_scan_with_ai_review_and_missing_api_key_still_exits_cleanly(capsys, monkeypatch):
    from mcpthreat_scan.analyzers.ai_review import AIReviewError

    def raise_missing_key(text):
        raise AIReviewError("OPENAI_API_KEY is not set.")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.review_candidate", raise_missing_key)

    exit_code = main(
        ["scan", "benchmark/vulnerable/tool_poisoning_docstring.py", "--ai-review"]
    )
    output = capsys.readouterr().out

    # DoD requirement: a missing key must not abort the scan (exit_code 0),
    # only leave the candidate unconfirmed with a visible note.
    assert exit_code == 0
    assert "Automatic layer-2 review not possible" in output


# ============================================================================
# P8-3: `diff <before> <after> [--format text|json]` subcommand tests. Only
# checks the CLI wiring (argument parsing, exit codes, missing-path
# handling) - the underlying rugpull diff logic itself is already proven in
# tests/test_rugpull_diff.py, and the report-shape wrapping in
# tests/test_report.py's build_diff_report() tests.
# ============================================================================

RUGPULL_DIR = "benchmark/rugpull"


def test_diff_default_format_is_readable_text(capsys):
    exit_code = main(
        ["diff", f"{RUGPULL_DIR}/example_email_bcc_v1.py", f"{RUGPULL_DIR}/example_email_bcc_v2.py"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "example_email_bcc_v2.py" in output
    assert "[Tool Poisoning]" in output
    assert "suspected rug pull" in output


def test_diff_format_json_is_valid_json(capsys):
    exit_code = main(
        [
            "diff",
            f"{RUGPULL_DIR}/example_search_schema_v1.py",
            f"{RUGPULL_DIR}/example_search_schema_v2.py",
            "--format",
            "json",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    assert len(parsed["findings"]) == 2
    assert all(f["category"] == "Tool Poisoning" for f in parsed["findings"])


def test_diff_identical_files_reports_no_findings(capsys):
    exit_code = main(
        ["diff", f"{RUGPULL_DIR}/example_search_schema_v1.py", f"{RUGPULL_DIR}/example_search_schema_v1.py"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No findings." in output


def test_diff_missing_before_path_returns_error_exit_code(capsys):
    exit_code = main(["diff", "does/not/exist.py", f"{RUGPULL_DIR}/example_email_bcc_v1.py"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "not found" in captured.err


def test_diff_missing_after_path_returns_error_exit_code(capsys):
    exit_code = main(["diff", f"{RUGPULL_DIR}/example_email_bcc_v1.py", "does/not/exist.py"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "not found" in captured.err


def test_scan_fail_on_error_triggers_error_exit_code_when_error_finding_present(capsys):
    exit_code = main(
        ["scan", "benchmark/vulnerable/command_injection.py", "--fail-on", "ERROR"]
    )

    assert exit_code == 1


def test_scan_fail_on_error_stays_zero_when_no_error_finding_present(capsys):
    exit_code = main(
        ["scan", "benchmark/vulnerable/unscoped_environ.py", "--fail-on", "ERROR"]
    )

    assert exit_code == 0


def test_scan_fail_on_warning_triggers_on_warning_finding(capsys):
    exit_code = main(
        ["scan", "benchmark/vulnerable/unscoped_environ.py", "--fail-on", "WARNING"]
    )

    assert exit_code == 1


def test_scan_without_fail_on_flag_stays_zero_even_with_error_finding(capsys):
    exit_code = main(["scan", "benchmark/vulnerable/command_injection.py"])

    assert exit_code == 0


def test_scan_single_file_skips_dependency_check(tmp_path, monkeypatch, capsys):
    target_file = tmp_path / "main.py"
    target_file.write_text("def handler():\n    pass\n", encoding="utf-8")

    def fail_if_called(path):
        raise AssertionError("check_requirements_file must not run for a single-file target")

    monkeypatch.setattr("mcpthreat_scan.core.orchestrator.check_requirements_file", fail_if_called)

    exit_code = main(["scan", str(target_file)])

    assert exit_code == 0


# ============================================================================
# P10-3: `--format sarif` wiring for both `scan` and `diff`. The SARIF
# rendering logic itself is already proven in tests/test_report.py - this
# file only checks that the CLI actually reaches render_sarif().
# ============================================================================


def test_scan_format_sarif_is_valid_sarif_json(capsys):
    exit_code = main(
        ["scan", "benchmark/vulnerable/command_injection.py", "--format", "sarif"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"][0]["ruleId"] == "command-injection"
    assert parsed["runs"][0]["results"][0]["level"] == "error"


def test_diff_format_sarif_is_valid_sarif_json(capsys):
    exit_code = main(
        [
            "diff",
            f"{RUGPULL_DIR}/example_email_bcc_v1.py",
            f"{RUGPULL_DIR}/example_email_bcc_v2.py",
            "--format",
            "sarif",
        ]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    parsed = json.loads(output)
    assert parsed["runs"][0]["results"][0]["ruleId"] == "tool-poisoning"
    assert parsed["runs"][0]["results"][0]["level"] == "error"
