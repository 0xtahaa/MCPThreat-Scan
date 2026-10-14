"""Characterization test (AR-087 X0c): JSON output bytes and key order (AR-086 D7).

json.dumps keeps insertion order, so key order is part of the output contract."""

import json

from mcpthreat_scan.core.orchestrator import run_diff, run_scan
from mcpthreat_scan.reporting.json import render_json

TOP_KEYS = ["target", "findings", "summary"]
FINDING_KEYS = ["category", "file", "line", "severity", "message"]
SUMMARY_KEYS = ["categories_checked", "categories_without_finding", "categories_with_finding"]
SCAN_FILE = "benchmark/vulnerable/command_injection.py"


def test_render_json_exact_bytes_for_fixed_report():
    report = {
        "target": "t",
        "findings": [{"category": "Header Leak", "file": "a.py", "line": None,
                      "severity": "INFO", "message": "Naïve é"}],
        "summary": {"categories_checked": 9, "categories_without_finding": 8,
                    "categories_with_finding": ["Header Leak"], "suppressed_count": 2},
    }
    expected = (
        '{\n  "target": "t",\n  "findings": [\n    {\n      "category": "Header Leak",\n'
        '      "file": "a.py",\n      "line": null,\n      "severity": "INFO",\n'
        '      "message": "Naïve é"\n    }\n  ],\n  "summary": {\n'
        '    "categories_checked": 9,\n    "categories_without_finding": 8,\n'
        '    "categories_with_finding": [\n      "Header Leak"\n    ],\n'
        '    "suppressed_count": 2\n  }\n}'
    )

    assert render_json(report) == expected


def test_scan_json_key_order_without_suppressed_count(tmp_path):
    report = run_scan(SCAN_FILE, ignore_file=tmp_path / "none")

    parsed = json.loads(render_json(report))

    assert list(parsed) == TOP_KEYS
    assert list(parsed["findings"][0]) == FINDING_KEYS
    assert list(parsed["summary"]) == SUMMARY_KEYS


def test_scan_json_puts_suppressed_count_last(tmp_path):
    finding = run_scan(SCAN_FILE, ignore_file=tmp_path / "none")["findings"][0]
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text(f"{finding['file']}:{finding['category']}\n", encoding="utf-8")

    parsed = json.loads(render_json(run_scan(SCAN_FILE, ignore_file=ignore_file)))

    assert list(parsed["summary"]) == SUMMARY_KEYS + ["suppressed_count"]


def test_diff_json_key_order_and_null_line():
    report = run_diff(
        "benchmark/rugpull/example_email_bcc_v1.py",
        "benchmark/rugpull/example_email_bcc_v2.py",
    )

    parsed = json.loads(render_json(report))

    assert list(parsed) == TOP_KEYS
    assert list(parsed["findings"][0]) == FINDING_KEYS
    assert parsed["findings"][0]["line"] is None
    assert list(parsed["summary"]) == SUMMARY_KEYS
