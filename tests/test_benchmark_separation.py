"""Benchmark evaluator lives outside the product (Phase 13, AR-159 to AR-165).

Static import checks plus real runs from the repository root. Only Layer 1 runs (no AI call: the
child processes get an empty OPENAI_API_KEY); the benchmark files are read, never executed."""

import ast
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import benchmark.evaluate as evaluator
from mcpthreat_scan.analyzers.semgrep import run_semgrep_rules

ROOT = Path(__file__).resolve().parent.parent
EVALUATE = ROOT / "benchmark" / "evaluate.py"
PRODUCT = ROOT / "src" / "mcpthreat_scan"

ALLOWED_EVALUATOR_IMPORTS = {
    "__future__",
    "json",
    "sys",
    "datetime",
    "pathlib",
    "mcpthreat_scan.core.models",
    "mcpthreat_scan.core.orchestrator",
}


def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            found.add(node.module or "")
    return found


def _run_module(module):
    env = dict(os.environ, OPENAI_API_KEY="")
    return subprocess.run(
        [sys.executable, "-m", module], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8"
    )


# --- direction of dependencies ---------------------------------------------------------------


def test_evaluator_imports_only_the_public_core_api_and_the_standard_library():
    assert _imports(EVALUATE) == ALLOWED_EVALUATOR_IMPORTS


def test_evaluator_does_not_import_legacy_packages_or_start_processes():
    imports = _imports(EVALUATE)

    for forbidden in ("scanner", "cli", "tui", "subprocess", "openai", "semgrep"):
        assert not any(name == forbidden or name.startswith(forbidden + ".") for name in imports)


def test_no_product_module_imports_benchmark_code():
    bad = []
    for path in sorted(PRODUCT.rglob("*.py")):
        for module in _imports(path):
            if module == "benchmark" or module.startswith("benchmark."):
                bad.append(f"{path.relative_to(ROOT).as_posix()} imports {module}")

    assert bad == []


def test_benchmark_is_not_part_of_the_installable_package():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert config["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    assert not (PRODUCT / "benchmark").exists()


def test_benchmark_package_marker_is_empty_and_the_new_files_produce_no_findings():
    assert (ROOT / "benchmark" / "__init__.py").read_bytes() == b""
    assert run_semgrep_rules(ROOT / "benchmark" / "__init__.py") == []
    assert run_semgrep_rules(EVALUATE) == []


# --- behaviour ---------------------------------------------------------------------------


def test_evaluator_scans_through_the_core_api_with_a_single_argument(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(evaluator, "run_scan", lambda *args, **kwargs: calls.append((args, kwargs)) or {"findings": []})
    expected = tmp_path / "expected.json"
    expected.write_text('{"a.py": {"expected": "clean", "categories": []}}', encoding="utf-8")

    evaluator.evaluate_benchmark(benchmark_root="somewhere", expected_results_path=expected)

    # no ai_review argument: the benchmark measures Layer 1 only
    assert calls == [(("somewhere",), {})]


def test_evaluator_has_no_private_scan_pipeline():
    assert not hasattr(evaluator, "build_report")
    assert evaluator.run_scan.__module__ == "mcpthreat_scan.core.orchestrator"


def test_evaluator_entry_point_prints_the_known_numbers():
    history_path = ROOT / "benchmark_history.jsonl"
    pre_existing_content = history_path.read_text(encoding="utf-8") if history_path.exists() else None

    try:
        result = _run_module("benchmark.evaluate")

        assert result.returncode == 0
        assert "Total: TP=29 FP=1 FN=2" in result.stdout
        assert result.stderr == ""
    finally:
        if pre_existing_content is None:
            history_path.unlink(missing_ok=True)
        else:
            history_path.write_text(pre_existing_content, encoding="utf-8")
