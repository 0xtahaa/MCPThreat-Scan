"""Precision/Recall evaluation: scan benchmark/ and compare against expected_results.json.

Measures Layer 1 only (Semgrep + OSV), not Layer 2 AI review. Reports honest metrics
including expected false positives from the Tool Poisoning candidate rule.

External quality consumer of the installable package: it uses the same core API as the CLI and
the TUI and never the other way round (no product module imports this file). Run it from the
repository root (`python -m benchmark.evaluate`): the expected-results keys are relative paths.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from mcpthreat_scan.core.models import VULNERABILITY_CATEGORIES
from mcpthreat_scan.core.orchestrator import run_scan

DEFAULT_BENCHMARK_ROOT = Path("benchmark")
DEFAULT_EXPECTED_RESULTS_PATH = Path("benchmark/expected_results.json")
DEFAULT_HISTORY_PATH = Path("benchmark_history.jsonl")


def _normalize_path(path_str: str) -> str:
    """Convert native path separators to forward slashes for cross-platform matching."""
    return Path(path_str).as_posix()


def load_expected_results(path: str | Path = DEFAULT_EXPECTED_RESULTS_PATH) -> dict:
    """Load benchmark/expected_results.json."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _findings_by_file(report: dict) -> dict[str, set[str]]:
    """Group findings by normalized file path and category set."""
    grouped: dict[str, set[str]] = {}
    for finding in report["findings"]:
        key = _normalize_path(finding["file"])
        grouped.setdefault(key, set()).add(finding["category"])
    return grouped


def _precision_recall(tp: int, fp: int, fn: int) -> tuple[float | None, float | None]:
    """Compute (precision, recall), returning None for undefined ratios (not 0.0)."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    return precision, recall


def evaluate_benchmark(
    benchmark_root: str | Path = DEFAULT_BENCHMARK_ROOT,
    expected_results_path: str | Path = DEFAULT_EXPECTED_RESULTS_PATH,
) -> dict:
    """Scan benchmark_root and score against expected_results.json at (file, category) granularity."""
    expected_results = load_expected_results(expected_results_path)
    report = run_scan(benchmark_root)
    found_by_file = _findings_by_file(report)

    # Initialize all categories to zero so uncovered ones show as "no test cases".
    per_category = {category: {"tp": 0, "fp": 0, "fn": 0} for category in VULNERABILITY_CATEGORIES}
    per_file_rows = []

    for file_key, entry in expected_results.items():
        expected_categories = set(entry.get("categories", []))
        found_categories = found_by_file.get(file_key, set())

        true_positive_categories = expected_categories & found_categories
        false_positive_categories = found_categories - expected_categories
        false_negative_categories = expected_categories - found_categories

        for category in true_positive_categories:
            per_category.setdefault(category, {"tp": 0, "fp": 0, "fn": 0})["tp"] += 1
        for category in false_positive_categories:
            per_category.setdefault(category, {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
        for category in false_negative_categories:
            per_category.setdefault(category, {"tp": 0, "fp": 0, "fn": 0})["fn"] += 1

        per_file_rows.append(
            {
                "file": file_key,
                "expected_categories": sorted(expected_categories),
                "found_categories": sorted(found_categories),
                "false_positives": sorted(false_positive_categories),
                "false_negatives": sorted(false_negative_categories),
            }
        )

    for counts in per_category.values():
        precision, recall = _precision_recall(counts["tp"], counts["fp"], counts["fn"])
        counts["precision"] = precision
        counts["recall"] = recall

    total_tp = sum(counts["tp"] for counts in per_category.values())
    total_fp = sum(counts["fp"] for counts in per_category.values())
    total_fn = sum(counts["fn"] for counts in per_category.values())
    overall_precision, overall_recall = _precision_recall(total_tp, total_fp, total_fn)

    return {
        "per_category": per_category,
        "overall": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": overall_precision,
            "recall": overall_recall,
        },
        "per_file": per_file_rows,
    }


def record_history(result: dict, history_path: str | Path = DEFAULT_HISTORY_PATH) -> None:
    """Append one timestamped line with the overall TP/FP/FN/precision/recall to history_path."""
    overall = result["overall"]
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tp": overall["tp"],
        "fp": overall["fp"],
        "fn": overall["fn"],
        "precision": overall["precision"],
        "recall": overall["recall"],
    }
    with Path(history_path).open("a", encoding="utf-8") as history_file:
        history_file.write(json.dumps(entry) + "\n")


def _format_ratio(value: float | None, empty_reason: str) -> str:
    """Format a precision/recall value as percentage or 'n/a' reason."""
    if value is None:
        return f"n/a ({empty_reason})"
    return f"{value:.0%}"


def render_text(result: dict) -> str:
    """Render evaluation result as human-readable terminal text."""
    lines = ["Precision/recall per OWASP MCP category (layer 1 - Semgrep + supply chain OSV check):"]

    for category in sorted(result["per_category"]):
        counts = result["per_category"][category]
        precision_str = _format_ratio(counts["precision"], "no findings")
        recall_str = _format_ratio(counts["recall"], "no test cases in the benchmark")
        lines.append(
            f"  {category}: TP={counts['tp']} FP={counts['fp']} FN={counts['fn']}"
            f" -> Precision={precision_str}, Recall={recall_str}"
        )

    overall = result["overall"]
    lines.append("")
    lines.append(
        f"Total: TP={overall['tp']} FP={overall['fp']} FN={overall['fn']}"
        f" -> Precision={_format_ratio(overall['precision'], 'no findings')},"
        f" Recall={_format_ratio(overall['recall'], 'no test cases in the benchmark')}"
    )

    files_with_false_positives = [row for row in result["per_file"] if row["false_positives"]]
    files_with_false_negatives = [row for row in result["per_file"] if row["false_negatives"]]

    if files_with_false_positives:
        lines.append("")
        lines.append("Files with unexpected findings (false positives):")
        for row in files_with_false_positives:
            lines.append(f"  {row['file']}: {', '.join(row['false_positives'])}")

    if files_with_false_negatives:
        lines.append("")
        lines.append("Files with missed findings (false negatives):")
        for row in files_with_false_negatives:
            lines.append(f"  {row['file']}: {', '.join(row['false_negatives'])}")

    return "\n".join(lines)


def main() -> int:
    """Print precision/recall benchmark report and append the overall numbers to the history file."""
    result = evaluate_benchmark()
    print(render_text(result))
    record_history(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
