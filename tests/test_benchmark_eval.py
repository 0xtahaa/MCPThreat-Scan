"""Tests for P6-1: precision/recall measurement.

Covers synthetic math verification and real benchmark evaluation."""

import json

import pytest

from benchmark.evaluate import evaluate_benchmark, record_history, render_text


def test_synthetic_true_positive_false_positive_and_false_negative(tmp_path, monkeypatch):
    expected_results = {
        "a.py": {"expected": "finding", "categories": ["Header Leak"]},
        "b.py": {"expected": "clean", "categories": []},
        "c.py": {"expected": "finding", "categories": ["Command Injection"]},
    }
    expected_path = tmp_path / "expected_results.json"
    expected_path.write_text(json.dumps(expected_results), encoding="utf-8")

    fake_report = {
        "findings": [
            {"category": "Header Leak", "file": "a.py", "line": 1, "severity": "ERROR", "message": "x"},
            {"category": "Tool Poisoning", "file": "b.py", "line": 2, "severity": "WARNING", "message": "y"},
        ]
    }
    monkeypatch.setattr("benchmark.evaluate.run_scan", lambda root: fake_report)

    result = evaluate_benchmark(benchmark_root="irrelevant", expected_results_path=expected_path)

    assert result["per_category"]["Header Leak"]["tp"] == 1
    assert result["per_category"]["Tool Poisoning"]["fp"] == 1
    assert result["per_category"]["Command Injection"]["fn"] == 1
    assert result["overall"] == {"tp": 1, "fp": 1, "fn": 1, "precision": 0.5, "recall": 0.5}


def test_category_with_no_benchmark_case_reports_none_not_zero(tmp_path, monkeypatch):
    expected_results = {"a.py": {"expected": "finding", "categories": ["Header Leak"]}}
    expected_path = tmp_path / "expected_results.json"
    expected_path.write_text(json.dumps(expected_results), encoding="utf-8")

    monkeypatch.setattr(
        "benchmark.evaluate.run_scan",
        lambda root: {
            "findings": [
                {"category": "Header Leak", "file": "a.py", "line": 1, "severity": "ERROR", "message": "x"}
            ]
        },
    )

    result = evaluate_benchmark(benchmark_root="irrelevant", expected_results_path=expected_path)

    assert result["per_category"]["Command Injection"] == {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "precision": None,
        "recall": None,
    }


def test_windows_style_backslash_paths_still_match_forward_slash_keys(tmp_path, monkeypatch):
    expected_results = {"dir/sub/file.py": {"expected": "finding", "categories": ["Header Leak"]}}
    expected_path = tmp_path / "expected_results.json"
    expected_path.write_text(json.dumps(expected_results), encoding="utf-8")

    monkeypatch.setattr(
        "benchmark.evaluate.run_scan",
        lambda root: {
            "findings": [
                {
                    "category": "Header Leak",
                    "file": "dir\\sub\\file.py",
                    "line": 1,
                    "severity": "ERROR",
                    "message": "x",
                }
            ]
        },
    )

    result = evaluate_benchmark(benchmark_root="irrelevant", expected_results_path=expected_path)

    assert result["per_category"]["Header Leak"]["tp"] == 1
    assert result["per_category"]["Header Leak"]["fn"] == 0


def test_real_benchmark_matches_documented_p6_1_numbers():
    """Verify benchmark evaluation against known reference numbers from P6-1."""
    result = evaluate_benchmark()

    assert result["per_category"]["Header Leak"] == {
        "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    assert result["per_category"]["Hardcoded Secret"] == {
        "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    assert result["per_category"]["Unscoped Environment Access"] == {
        "tp": 5, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    assert result["per_category"]["Command Injection"] == {
        "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    assert result["per_category"]["Tool Poisoning"]["tp"] == 6
    assert result["per_category"]["Tool Poisoning"]["fp"] == 1
    assert result["per_category"]["Tool Poisoning"]["fn"] == 2
    assert result["per_category"]["Tool Poisoning"]["precision"] == pytest.approx(6 / 7)
    assert result["per_category"]["Tool Poisoning"]["recall"] == pytest.approx(0.75)
    # P12-5c: the node manifest fixture added a second Supply Chain true positive.
    assert result["per_category"]["Supply Chain"] == {
        "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    # P12-5e: the TypeScript typosquat fixture added a second Typosquatting true positive.
    assert result["per_category"]["Typosquatting / Shadow-Server"] == {
        "tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }
    assert result["per_category"]["Missing Audit Logging"] == {
        "tp": 6, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0
    }

    assert result["overall"]["tp"] == 29
    assert result["overall"]["fp"] == 1
    assert result["overall"]["fn"] == 2
    assert result["overall"]["precision"] == pytest.approx(29 / 30)
    assert result["overall"]["recall"] == pytest.approx(29 / 31)


def test_render_text_names_the_known_false_positive_and_false_negatives():
    result = evaluate_benchmark()

    text = render_text(result)

    assert "example_server_appointments.py: Tool Poisoning" in text
    assert "example_email_bcc_v2.py: Tool Poisoning" in text
    assert "example_search_schema_v2.py: Tool Poisoning" in text
    assert "Total:" in text


def test_record_history_appends_one_json_line(tmp_path):
    history_path = tmp_path / "benchmark_history.jsonl"
    fake_result = {"overall": {"tp": 5, "fp": 1, "fn": 2, "precision": 0.83, "recall": 0.71}}

    record_history(fake_result, history_path=history_path)

    lines = history_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tp"] == 5
    assert entry["fp"] == 1
    assert entry["fn"] == 2
    assert entry["precision"] == 0.83
    assert entry["recall"] == 0.71
    assert "timestamp" in entry


def test_record_history_appends_not_overwrites(tmp_path):
    history_path = tmp_path / "benchmark_history.jsonl"
    fake_result = {"overall": {"tp": 1, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0}}

    record_history(fake_result, history_path=history_path)
    record_history(fake_result, history_path=history_path)

    lines = history_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


def test_record_history_two_consecutive_runs_have_different_timestamps_same_numbers(tmp_path):
    """Direct DoD check: two consecutive real evaluate_benchmark() runs -> two entries,
    different timestamp, same numbers, since the underlying code did not change."""
    history_path = tmp_path / "benchmark_history.jsonl"

    result_1 = evaluate_benchmark()
    record_history(result_1, history_path=history_path)
    result_2 = evaluate_benchmark()
    record_history(result_2, history_path=history_path)

    lines = history_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    entry_1, entry_2 = json.loads(lines[0]), json.loads(lines[1])
    assert entry_1["timestamp"] != entry_2["timestamp"]
    assert {k: v for k, v in entry_1.items() if k != "timestamp"} == {
        k: v for k, v in entry_2.items() if k != "timestamp"
    }


def test_record_history_handles_none_precision_recall(tmp_path):
    """Supply Chain category has no test cases -> precision/recall are None, must stay valid JSON."""
    history_path = tmp_path / "benchmark_history.jsonl"
    fake_result = {"overall": {"tp": 0, "fp": 0, "fn": 0, "precision": None, "recall": None}}

    record_history(fake_result, history_path=history_path)

    entry = json.loads(history_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["precision"] is None
    assert entry["recall"] is None
