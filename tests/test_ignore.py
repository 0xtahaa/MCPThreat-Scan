"""Tests for P10-1: .mcpscannerignore suppression mechanism."""

from mcpthreat_scan.policy.ignore import apply_ignore_rules, load_ignore_rules


def test_missing_ignore_file_returns_no_rules(tmp_path):
    missing_path = tmp_path / ".mcpscannerignore"

    assert load_ignore_rules(missing_path) == set()


def test_parses_valid_line_into_rule(tmp_path):
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text("benchmark/clean/example.py:Tool Poisoning\n", encoding="utf-8")

    assert load_ignore_rules(ignore_file) == {("benchmark/clean/example.py", "Tool Poisoning")}


def test_skips_comments_and_blank_lines(tmp_path):
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text(
        "# this is a comment\n\nbenchmark/clean/example.py:Tool Poisoning\n",
        encoding="utf-8",
    )

    assert load_ignore_rules(ignore_file) == {("benchmark/clean/example.py", "Tool Poisoning")}


def test_skips_line_without_colon(tmp_path):
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text("this is not a valid line\n", encoding="utf-8")

    assert load_ignore_rules(ignore_file) == set()


def test_splits_on_last_colon_for_windows_style_paths(tmp_path):
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text(r"C:\projekte\server.py:Tool Poisoning" + "\n", encoding="utf-8")

    assert load_ignore_rules(ignore_file) == {(r"C:\projekte\server.py", "Tool Poisoning")}


def test_strips_whitespace_around_path_and_category(tmp_path):
    ignore_file = tmp_path / ".mcpscannerignore"
    ignore_file.write_text("  benchmark/x.py :  Tool Poisoning  \n", encoding="utf-8")

    assert load_ignore_rules(ignore_file) == {("benchmark/x.py", "Tool Poisoning")}


def test_apply_with_no_rules_keeps_all_findings():
    findings = [{"file": "a.py", "category": "Header Leak"}]

    kept, suppressed_count = apply_ignore_rules(findings, set())

    assert kept == findings
    assert suppressed_count == 0


def test_apply_removes_matching_finding_and_counts_it():
    findings = [{"file": "a.py", "category": "Tool Poisoning"}]
    rules = {("a.py", "Tool Poisoning")}

    kept, suppressed_count = apply_ignore_rules(findings, rules)

    assert kept == []
    assert suppressed_count == 1


def test_apply_keeps_finding_with_different_category_at_same_path():
    findings = [{"file": "a.py", "category": "Hardcoded Secret"}]
    rules = {("a.py", "Tool Poisoning")}

    kept, suppressed_count = apply_ignore_rules(findings, rules)

    assert kept == findings
    assert suppressed_count == 0


def test_apply_only_removes_matching_findings_from_mixed_list():
    findings = [
        {"file": "a.py", "category": "Tool Poisoning"},
        {"file": "b.py", "category": "Header Leak"},
    ]
    rules = {("a.py", "Tool Poisoning")}

    kept, suppressed_count = apply_ignore_rules(findings, rules)

    assert kept == [{"file": "b.py", "category": "Header Leak"}]
    assert suppressed_count == 1
