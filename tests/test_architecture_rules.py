"""Import-graph guards for the package layout (AR-097, AR-098; rules C, D/F, E, G of AR-024).

Static AST scan only - no module is imported or executed."""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "src" / "mcpthreat_scan"
PKG = "mcpthreat_scan"
UI_MODULES = {f"{PKG}.cli", f"{PKG}.tui", "argparse", "textual", "rich", "click", "typer"}


def _modules(package_dir: str):
    for path in sorted((ROOT / package_dir).rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def _imports(tree: ast.AST) -> set[str]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports are not allowed"
            found.add(node.module or "")
    return found


def _matches(module: str, prefixes: set[str]) -> bool:
    return any(module == p or module.startswith(p + ".") for p in prefixes)


def _violations(package_dir, forbidden, allow=lambda path, module: False):
    bad = []
    for path, tree in _modules(package_dir):
        for module in _imports(tree):
            if _matches(module, forbidden) and not allow(path, module):
                bad.append(f"{path.relative_to(ROOT)} imports {module}")
    return bad


def test_core_contains_no_rendering_or_ui_imports():
    # AR-097 / rules D, I: the orchestrator returns a result dict; formats live elsewhere.
    forbidden = UI_MODULES | {"json", f"{PKG}.reporting"}

    assert _violations("core", forbidden) == []


def test_core_builds_no_serialized_output():
    bad = []
    for path, tree in _modules("core"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"dumps", "dump"}:
                    bad.append(f"{path.name}: .{node.func.attr}(")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                bad.append(f"{path.name}: print(")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "sarif" in node.value.lower():
                bad.append(f"{path.name}: SARIF literal")

    assert bad == []


def test_analyzers_import_no_ui():
    # AR-098 / rule E
    assert _violations("analyzers", UI_MODULES) == []


def test_analyzers_do_not_print():
    bad = []
    for path, tree in _modules("analyzers"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                bad.append(path.name)

    assert bad == []


def test_analyzers_import_no_sibling_analyzer_diff_policy_or_core():
    # rule C: only the orchestrator combines analyzers
    forbidden = {f"{PKG}.analyzers", f"{PKG}.diff", f"{PKG}.policy", f"{PKG}.core", f"{PKG}.reporting"}

    assert _violations("analyzers", forbidden, allow=lambda p, m: False) == []


@pytest.mark.parametrize("package_dir", ["reporting", "diff", "policy"])
def test_passive_packages_import_no_ui(package_dir):
    # rule F (reporting) and general: no UI below the presentation layer
    assert _violations(package_dir, UI_MODULES) == []


def test_reporting_does_not_import_the_orchestrator_or_analysis_code():
    # rule D
    forbidden = {
        f"{PKG}.core.orchestrator", f"{PKG}.analyzers", f"{PKG}.policy", f"{PKG}.diff",
    }

    assert _violations("reporting", forbidden) == []


def test_product_never_imports_benchmark():
    # rule G
    bad = []
    for path in sorted(ROOT.rglob("*.py")):
        for module in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            if module == "benchmark" or module.startswith("benchmark."):
                bad.append(f"{path.relative_to(ROOT)} imports {module}")

    assert bad == []


# importlib.metadata only reads installed-package metadata (version lookup) and loads no code;
# every other importlib module (import_module, util, machinery, ...) stays forbidden.
ALLOWED_IMPORTLIB = {"importlib.metadata"}


def _importlib_violations(tree):
    return [
        module
        for module in _imports(tree)
        if (module == "importlib" or module.startswith("importlib.")) and module not in ALLOWED_IMPORTLIB
    ]


def test_no_dynamic_code_execution_in_product_code():
    # Zero-Execution: no eval/exec/__import__/importlib on scan targets anywhere in the package
    bad = []
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec", "__import__"}:
                    bad.append(f"{path.relative_to(ROOT)}: {node.func.id}(")
        bad += [f"{path.relative_to(ROOT)} imports {module}" for module in _importlib_violations(tree)]

    assert bad == []


def test_importlib_guard_allows_only_the_metadata_module():
    tree = ast.parse(
        "import importlib\n"
        "import importlib.util\n"
        "from importlib import import_module\n"
        "from importlib.metadata import version\n"
        "import importlib.metadata\n"
    )

    assert sorted(_importlib_violations(tree)) == ["importlib", "importlib.util"]


# Phase 8 (AR-105 to AR-108): no models, no class hierarchies, analyzers stay functions.
# The map is exact on purpose: adding any class (data model, analyzer class, base class)
# fails this test until the decision is documented in docs/ARCHITECTURE.md and the map is updated.
LOGIC_PACKAGES = ["core", "analyzers", "policy", "diff", "reporting"]
EXPECTED_CLASSES = {
    "analyzers/ai_review.py": {"AIReviewError"},
    "analyzers/dependencies.py": {"DependencyCheckError"},
    "analyzers/semgrep.py": {"SemgrepRunnerError"},
    "core/exceptions.py": {"ReportError"},
}
MODEL_LIBRARY_MODULES = {"dataclasses", "enum", "pydantic", "attrs"}
MODEL_LIBRARY_TYPING_NAMES = {"TypedDict", "NamedTuple"}


def _defined_classes(package_dirs):
    found = {}
    for package_dir in package_dirs:
        for path, tree in _modules(package_dir):
            names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
            if names:
                found[path.relative_to(ROOT).as_posix()] = names
    return found


def test_logic_packages_define_only_the_controlled_exceptions():
    assert _defined_classes(LOGIC_PACKAGES) == EXPECTED_CLASSES


def test_controlled_exceptions_are_flat_subclasses_of_runtimeerror():
    # AR-106: no custom base classes; each exception derives directly from RuntimeError.
    bad = []
    for package_dir in LOGIC_PACKAGES:
        for path, tree in _modules(package_dir):
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = [ast.unparse(base) for base in node.bases]
                    if bases != ["RuntimeError"] or node.decorator_list:
                        bad.append(f"{path.relative_to(ROOT).as_posix()}: {node.name}({', '.join(bases)})")

    assert bad == []


def test_logic_packages_import_no_model_libraries():
    bad = []
    for package_dir in LOGIC_PACKAGES:
        for path, tree in _modules(package_dir):
            for module in _imports(tree):
                if _matches(module, MODEL_LIBRARY_MODULES):
                    bad.append(f"{path.relative_to(ROOT).as_posix()} imports {module}")
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "typing":
                    for alias in node.names:
                        if alias.name in MODEL_LIBRARY_TYPING_NAMES:
                            bad.append(f"{path.relative_to(ROOT).as_posix()} imports typing.{alias.name}")

    assert bad == []


def test_class_guard_detects_a_data_model(tmp_path, monkeypatch):
    # Effectiveness check: a dataclass added to core must break the exact class map
    # and be reported by the model-library import check.
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "models_new.py").write_text(
        "from dataclasses import dataclass\n"
        "from typing import TypedDict\n"
        "@dataclass\nclass Finding:\n    file: str\n"
        "class Row(TypedDict):\n    line: int\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(f"{__name__}.ROOT", tmp_path)

    assert _defined_classes(["core"]) == {"core/models_new.py": {"Finding", "Row"}}
    imports = {m for _, tree in _modules("core") for m in _imports(tree)}
    assert any(_matches(m, MODEL_LIBRARY_MODULES) for m in imports)


# Phase 9 (AR-119): reporting is a pure view layer - stdlib plus passive core contracts only.
REPORTING_ALLOWED_IMPORTS = {"__future__", "json", "pathlib", f"{PKG}.core.models", f"{PKG}.core.exceptions"}
REPORTING_FORBIDDEN_CALLS = {"open", "print", "input", "eval", "exec", "compile"}
REPORTING_FORBIDDEN_METHODS = {
    "read_text", "read_bytes", "write_text", "write_bytes", "open", "exists", "is_file", "is_dir",
    "iterdir", "glob", "rglob", "mkdir", "unlink", "resolve", "stat",
}


def _reporting_violations(tree):
    bad = [f"imports {m}" for m in _imports(tree) if m not in REPORTING_ALLOWED_IMPORTS]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in REPORTING_FORBIDDEN_CALLS:
                bad.append(f"calls {node.func.id}()")
            if isinstance(node.func, ast.Attribute) and node.func.attr in REPORTING_FORBIDDEN_METHODS:
                bad.append(f"calls .{node.func.attr}()")
    return bad


def test_reporting_imports_only_stdlib_and_passive_core_contracts():
    # Stricter than rule D: an exact allow-list, so any new dependency needs a documented decision.
    bad = []
    for path, tree in _modules("reporting"):
        bad += [f"{path.name} {issue}" for issue in _reporting_violations(tree)]

    assert bad == []


def test_reporting_contains_the_three_renderers():
    names = sorted(path.name for path, _ in _modules("reporting"))

    assert names == ["__init__.py", "json.py", "sarif.py", "text.py"]


def test_reporting_guard_detects_io_and_analysis_imports():
    tree = ast.parse(
        f"import subprocess\nfrom {PKG}.analyzers.semgrep import run_semgrep_rules\n"
        "def f(path):\n    print(open(path).read())\n    return path.exists()\n"
    )

    issues = _reporting_violations(tree)

    assert "imports subprocess" in issues
    assert f"imports {PKG}.analyzers.semgrep" in issues
    assert {"calls print()", "calls open()", "calls .exists()"} <= set(issues)


# Phase 10 (AR-125): the target CLI only wires arguments to the core API and the renderers.
CLI_ALLOWED_IMPORTS = {
    "__future__", "argparse", "sys", "pathlib", "collections.abc", "functools",
    f"{PKG}.core.orchestrator", f"{PKG}.core.models", f"{PKG}.core.exceptions",
    f"{PKG}.reporting.json", f"{PKG}.reporting.sarif", f"{PKG}.reporting.text",
    f"{PKG}.tui.app",  # lazy start of the target TUI (Phase 11)
}


def _cli_violations(tree):
    return [m for m in _imports(tree) if m not in CLI_ALLOWED_IMPORTS]


def test_target_cli_imports_only_stdlib_core_api_and_reporting():
    # Rule A/B: no analyzer, policy, diff or legacy import, no second pipeline; exact allow-list.
    bad = []
    for path, tree in _modules("cli"):
        bad += [f"{path.name} imports {m}" for m in _cli_violations(tree)]

    assert bad == []


def test_target_cli_starts_no_processes_and_reads_no_files():
    bad = []
    for path, tree in _modules("cli"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"open", "eval", "exec"}:
                bad.append(f"{path.name}: {node.func.id}(")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes", "run", "Popen"}:
                    bad.append(f"{path.name}: .{node.func.attr}(")

    assert bad == []


def test_cli_guard_detects_analyzer_policy_diff_and_legacy_imports():
    tree = ast.parse(
        f"from {PKG}.analyzers.semgrep import run_semgrep_rules\n"
        f"from {PKG}.policy.ignore import load_ignore_rules\n"
        f"from {PKG}.diff.rugpull import diff_tool_schema_files\n"
        "from scanner.report import build_report\n"
        "import subprocess\n"
    )

    assert sorted(_cli_violations(tree)) == sorted([
        f"{PKG}.analyzers.semgrep", f"{PKG}.policy.ignore", f"{PKG}.diff.rugpull",
        "scanner.report", "subprocess",
    ])


# Phase 11 (AR-135, AR-136): the target TUI presents and navigates; analysis, store formats and
# legacy paths stay out. Direct file writes are allowed in setup.py (.env key storage) and export.py (report export) only.
TUI_FORBIDDEN_IMPORTS = {
    f"{PKG}.analyzers", f"{PKG}.diff", f"{PKG}.cli", f"{PKG}.core.config",
    "scanner", "tui", "cli", "benchmark", "subprocess", "json", "socket", "urllib", "http", "requests", "openai",
}
TUI_WRITE_CALLS = {"write_text", "write_bytes", "open", "mkdir", "unlink", "rename", "replace"}


def _tui_import_violations(tree):
    return [m for m in _imports(tree) if _matches(m, TUI_FORBIDDEN_IMPORTS)]


def test_target_tui_imports_no_analysis_diff_cli_legacy_or_store_format_modules():
    bad = []
    for path, tree in _modules("tui"):
        bad += [f"{path.relative_to(ROOT).as_posix()} imports {m}" for m in _tui_import_violations(tree)]

    assert bad == []


def test_target_tui_uses_only_the_core_api_and_policy_functions():
    allowed = {
        f"{PKG}.core.orchestrator", f"{PKG}.core.exceptions", f"{PKG}.core.models",
        f"{PKG}.policy.ignore", f"{PKG}.policy.reputation",
        f"{PKG}.reporting.json", f"{PKG}.reporting.sarif",  # export dialog: same renderers as the CLI
    }
    used = set()
    for path, tree in _modules("tui"):
        used |= {m for m in _imports(tree) if m.startswith(f"{PKG}.") and not _matches(m, {f"{PKG}.tui"})}

    assert used == allowed


def test_target_tui_writes_no_files_except_the_env_key_in_setup():
    bad = []
    for path, tree in _modules("tui"):
        if path.name in {"setup.py", "export.py"}:  # API-key file / the user's report export
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
                if name in TUI_WRITE_CALLS:
                    bad.append(f"{path.relative_to(ROOT).as_posix()}: {name}(")

    assert bad == []


def test_target_tui_never_runs_scanned_code_or_processes():
    bad = []
    for path, tree in _modules("tui"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "__import__"}:
                bad.append(f"{path.name}: {node.func.id}(")

    assert bad == []


def test_tui_guard_detects_legacy_analysis_and_store_imports():
    tree = ast.parse(
        "from scanner.report import build_report\n"
        f"from {PKG}.analyzers.semgrep import run_semgrep_rules\n"
        "import json\n"
        "from tui.theme import ACCENT\n"
    )

    assert sorted(_tui_import_violations(tree)) == sorted(
        ["scanner.report", f"{PKG}.analyzers.semgrep", "json", "tui.theme"]
    )
