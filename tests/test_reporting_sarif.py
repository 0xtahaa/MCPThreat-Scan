"""Renderer tests for reporting/sarif.py (AR-118b, AR-120).

Pure tests: finished reports go in, SARIF text comes out; no scan, no paths, no files."""

import json
import os

import pytest

from mcpthreat_scan.core.models import REMEDIATION_BY_CATEGORY, VULNERABILITY_CATEGORIES
from mcpthreat_scan.reporting.sarif import render_sarif

SUMMARY = {"categories_checked": 9, "categories_without_finding": 9, "categories_with_finding": []}


def _finding(category="Header Leak", file="src/a.py", line=9, severity="ERROR", message="m"):
    return {"category": category, "file": file, "line": line, "severity": severity, "message": message}


def _report(*findings):
    return {"target": "x", "findings": list(findings), "summary": SUMMARY}


def _render(*findings):
    return json.loads(render_sarif(_report(*findings)))


def test_top_level_fields_and_tool_metadata_are_fixed():
    sarif = _render()

    assert sarif["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    )
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("mcpthreat-scan", "0.1.0")


def test_rule_catalog_lists_all_nine_categories_even_without_findings():
    rules = _render()["runs"][0]["tool"]["driver"]["rules"]

    assert [rule["name"] for rule in rules] == VULNERABILITY_CATEGORIES
    assert rules[0] == {
        "id": "header-leak",
        "name": "Header Leak",
        "shortDescription": {"text": "Header Leak"},
        "help": {"text": REMEDIATION_BY_CATEGORY["Header Leak"]},
    }
    assert rules[-1]["id"] == "typosquatting-/-shadow-server"
    assert _render()["runs"][0]["results"] == []


def test_result_maps_finding_fields_and_omits_region_without_line():
    results = _render(_finding(line=9), _finding(category="Supply Chain", file="requirements.txt", line=None))["runs"][0]["results"]

    with_line, without_line = results
    assert with_line["ruleId"] == "header-leak"
    assert with_line["message"] == {"text": "m"}
    assert with_line["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "src/a.py"},
        "region": {"startLine": 9},
    }
    assert without_line["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "requirements.txt"}}


def test_line_zero_still_produces_a_region():
    result = _render(_finding(line=0))["runs"][0]["results"][0]

    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 0}


def test_severities_map_to_sarif_levels():
    results = _render(
        _finding(severity="INFO"), _finding(severity="WARNING"), _finding(severity="ERROR")
    )["runs"][0]["results"]

    assert [r["level"] for r in results] == ["note", "warning", "error"]


def test_unknown_category_uses_rule_id_other():
    result = _render(_finding(category="Unknown Category"))["runs"][0]["results"][0]

    assert result["ruleId"] == "other"


def test_unknown_severity_raises_key_error():
    # Documents D4/I4: the vocabulary is closed but not validated; behaviour is unchanged by the move.
    with pytest.raises(KeyError):
        render_sarif(_report(_finding(severity="CRITICAL")))


def test_one_result_per_finding_in_input_order():
    findings = [_finding(message=f"m{i}", line=i + 1) for i in range(4)]

    results = _render(*findings)["runs"][0]["results"]

    assert [r["message"]["text"] for r in results] == ["m0", "m1", "m2", "m3"]


def test_summary_and_target_are_not_part_of_the_output():
    text = render_sarif(_report(_finding()))

    assert "categories_checked" not in text
    assert '"target"' not in text


@pytest.mark.skipif(os.name != "nt", reason="backslash is a path separator only on Windows")
def test_windows_separators_become_forward_slashes():
    result = _render(_finding(file="benchmark\\vulnerable\\a.py"))["runs"][0]["results"][0]

    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "benchmark/vulnerable/a.py"


def test_render_sarif_does_not_mutate_the_report():
    report = _report(_finding())
    before = repr(report)

    render_sarif(report)

    assert repr(report) == before


def test_evidence_becomes_the_region_snippet_and_the_scanner_rule_id_a_property():
    finding = {**_finding(line=9), "rule_id": "header-dump-candidate", "evidence": "headers = request.headers"}

    result = _render(finding)["runs"][0]["results"][0]

    assert result["ruleId"] == "header-leak"  # stable category id is unchanged
    assert result["properties"] == {"scannerRuleId": "header-dump-candidate"}
    assert result["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 9,
        "snippet": {"text": "headers = request.headers"},
    }


def test_findings_without_the_new_fields_still_render():
    result = _render(_finding(line=9))["runs"][0]["results"][0]

    assert "properties" not in result
    assert "snippet" not in result["locations"][0]["physicalLocation"]["region"]
