"""Renderer tests for reporting/json.py (AR-118, AR-120).

Pure tests: finished reports go in, strings come out; no scan, no paths, no files."""

import json as stdlib_json

import pytest

import mcpthreat_scan.reporting.json as reporting_json
from mcpthreat_scan.reporting.json import render_json

REPORT = {
    "target": "srv",
    "findings": [
        {"category": "Header Leak", "file": "a.py", "line": 9, "severity": "ERROR", "message": "Café – ñçü \U0001F512"},
        {"category": "Supply Chain", "file": "requirements.txt", "line": None, "severity": "ERROR", "message": "x"},
    ],
    "summary": {
        "categories_checked": 9,
        "categories_without_finding": 7,
        "categories_with_finding": ["Header Leak", "Supply Chain"],
        "suppressed_count": 1,
    },
}


def test_module_named_json_still_uses_the_standard_library():
    assert reporting_json.json is stdlib_json


def test_render_json_round_trips_to_the_same_report():
    assert stdlib_json.loads(render_json(REPORT)) == REPORT


def test_render_json_keeps_key_order_and_writes_null_for_missing_line():
    parsed = stdlib_json.loads(render_json(REPORT))

    assert list(parsed) == ["target", "findings", "summary"]
    assert list(parsed["findings"][0]) == ["category", "file", "line", "severity", "message"]
    assert list(parsed["summary"]) == [
        "categories_checked", "categories_without_finding", "categories_with_finding", "suppressed_count",
    ]
    assert parsed["findings"][1]["line"] is None
    assert '"line": null' in render_json(REPORT)


def test_render_json_uses_two_space_indent_without_trailing_newline():
    text = render_json(REPORT)

    assert text.startswith('{\n  "target": "srv",\n  "findings": [\n    {\n      "category"')
    assert not text.endswith("\n")


def test_render_json_writes_unicode_unescaped():
    text = render_json(REPORT)

    assert "Café – ñçü \U0001F512" in text
    assert "\\u" not in text


def test_render_json_does_not_mutate_the_report():
    report = stdlib_json.loads(stdlib_json.dumps(REPORT))
    before = repr(report)

    render_json(report)

    assert repr(report) == before


def test_render_json_rejects_values_that_are_not_serializable():
    with pytest.raises(TypeError):
        render_json({"target": object(), "findings": [], "summary": {}})
