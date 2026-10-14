"""Exact-output tests for reporting/text.py (AR-114, AR-120).

Pure renderer tests: fixed finished reports go in, strings come out. No scan, no paths,
no files are touched."""

from mcpthreat_scan.reporting.text import render_text

SUMMARY_EMPTY = {"categories_checked": 9, "categories_without_finding": 9, "categories_with_finding": []}


def _finding(category, file, line, severity, message):
    return {"category": category, "file": file, "line": line, "severity": severity, "message": message}


def test_clean_report_text_is_exact():
    report = {"target": "x", "findings": [], "summary": SUMMARY_EMPTY}

    assert render_text(report) == (
        "No findings.\n\nSummary: 9 of 9 OWASP MCP categories without findings."
    )


def test_mixed_report_text_is_exact():
    # Unicode, Windows path, line=None (Supply Chain vs. other), unknown category, suppression.
    report = {
        "target": "srv",
        "findings": [
            _finding("Header Leak", "b\\srv.py", 9, "ERROR", "Café – ñçü \U0001F512"),
            _finding("Missing Audit Logging", "a/srv.py", 3, "INFO", "n"),
            _finding("Supply Chain", "requirements.txt", None, "ERROR", "urllib3==1.26.4: CVE-1"),
            _finding("Tool Poisoning", "a/srv.py", None, "WARNING", "d"),
            _finding("Unknown Category", "c.py", 1, "WARNING", "u"),
        ],
        "summary": {
            "categories_checked": 9,
            "categories_without_finding": 5,
            "categories_with_finding": ["Header Leak", "Missing Audit Logging", "Supply Chain", "Tool Poisoning"],
            "suppressed_count": 2,
        },
    }

    assert render_text(report) == (
        "a/srv.py:\n"
        "  Line 3 [Missing Audit Logging] INFO: n\n"
        "  no line reference [Tool Poisoning] WARNING: d\n"
        "b\\srv.py:\n"
        "  Line 9 [Header Leak] ERROR: Café – ñçü \U0001F512\n"
        "c.py:\n"
        "  Line 1 [Unknown Category] WARNING: u\n"
        "requirements.txt:\n"
        "  Package [Supply Chain] ERROR: urllib3==1.26.4: CVE-1\n"
        "\n"
        "Summary: 5 of 9 OWASP MCP categories without findings.\n"
        "Categories with findings: Header Leak, Missing Audit Logging, Supply Chain, Tool Poisoning\n"
        "2 finding(s) suppressed by .mcpscannerignore."
    )


def test_suppressed_line_only_appears_for_positive_count():
    zero = {"target": "x", "findings": [], "summary": {**SUMMARY_EMPTY, "suppressed_count": 0}}
    absent = {"target": "x", "findings": [], "summary": SUMMARY_EMPTY}

    assert render_text(zero) == render_text(absent)
    assert "suppressed" not in render_text(zero)


def test_diff_finding_without_line_says_kein_zeilenbezug_not_paket():
    report = {
        "target": "a -> b",
        "findings": [_finding("Tool Poisoning", "b.py", None, "ERROR", "Rug-Pull")],
        "summary": {**SUMMARY_EMPTY, "categories_without_finding": 8, "categories_with_finding": ["Tool Poisoning"]},
    }

    text = render_text(report)

    assert "  no line reference [Tool Poisoning] ERROR: Rug-Pull" in text
    assert "Package" not in text


def test_line_zero_is_a_real_line_number():
    report = {"target": "x", "findings": [_finding("Header Leak", "a.py", 0, "INFO", "m")], "summary": SUMMARY_EMPTY}

    assert "  Line 0 [Header Leak] INFO: m" in render_text(report)


def test_renderer_does_not_mutate_the_report():
    report = {"target": "x", "findings": [_finding("Header Leak", "a.py", 1, "INFO", "m")], "summary": dict(SUMMARY_EMPTY)}
    before = repr(report)

    render_text(report)

    assert repr(report) == before
