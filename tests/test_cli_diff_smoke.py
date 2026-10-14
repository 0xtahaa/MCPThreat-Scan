"""Diff command through both start paths: AR-010 diff invariants, formats, error cases (AR-130).

Pure AST diff on the rug-pull fixtures; no Semgrep, no network."""

import json

import pytest

import mcpthreat_scan.cli.main as target

R = "benchmark/rugpull/"
EMAIL_V1, EMAIL_V2 = R + "example_email_bcc_v1.py", R + "example_email_bcc_v2.py"
SCHEMA_V1, SCHEMA_V2 = R + "example_search_schema_v1.py", R + "example_search_schema_v2.py"


@pytest.fixture
def cli_main():
    return target.main


def _run(cli_main, capsys, *argv):
    exit_code = cli_main(list(argv))
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_hidden_behavior_change_is_reported_as_error_in_text(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "diff", EMAIL_V1, EMAIL_V2)

    assert exit_code == 0
    assert "Tool Poisoning" in out and "ERROR" in out and "suspected rug pull" in out
    assert "no line reference" in out and "Package" not in out


def test_schema_change_json_has_exactly_two_tool_poisoning_findings(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "diff", SCHEMA_V1, SCHEMA_V2, "--format", "json")

    report = json.loads(out)
    assert exit_code == 0
    assert [f["category"] for f in report["findings"]] == ["Tool Poisoning", "Tool Poisoning"]
    assert [f["severity"] for f in report["findings"]] == ["WARNING", "WARNING"]
    assert all(f["line"] is None for f in report["findings"])
    assert "suppressed_count" not in report["summary"]
    assert " -> " in report["target"]


def test_sarif_result_has_tool_poisoning_rule_and_error_level(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "diff", EMAIL_V1, EMAIL_V2, "--format", "sarif")

    sarif = json.loads(out)
    result = sarif["runs"][0]["results"][0]
    assert (exit_code, sarif["version"]) == (0, "2.1.0")
    assert (result["ruleId"], result["level"]) == ("tool-poisoning", "error")
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_identical_files_report_no_findings(cli_main, capsys):
    exit_code, out, _ = _run(cli_main, capsys, "diff", EMAIL_V1, EMAIL_V1)

    assert exit_code == 0
    assert "No findings." in out


def test_diff_never_fails_on_findings_and_has_no_fail_on_option(cli_main, capsys):
    assert _run(cli_main, capsys, "diff", EMAIL_V1, EMAIL_V2)[0] == 0  # ERROR finding, still exit 0
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["diff", EMAIL_V1, EMAIL_V2, "--fail-on", "ERROR"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("missing", ["before", "after"])
def test_missing_path_is_reported_with_exit_one(cli_main, capsys, missing):
    args = ["diff", "does/not/exist.py", EMAIL_V2] if missing == "before" else ["diff", EMAIL_V1, "does/not/exist.py"]

    exit_code, out, err = _run(cli_main, capsys, *args)

    assert exit_code == 1
    assert "Path not found: does" in err
    assert out == ""


def test_unparsable_file_becomes_a_controlled_rugpull_error(cli_main, capsys, tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    exit_code, out, err = _run(cli_main, capsys, "diff", str(broken), EMAIL_V2)

    assert exit_code == 1
    assert err.startswith("Rug-pull diff error:")
    assert out == ""
