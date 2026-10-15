"""No speculative abstractions in the product package (Phase 15, AR-192 and AR-193).

Static AST scan. The class inventory is exact on purpose: a new class anywhere in
src/mcpthreat_scan fails here until it has a named consumer and is documented in
docs/ARCHITECTURE.md ("Naming and simplification")."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "src" / "mcpthreat_scan"

# class -> base class, by module path relative to the package
EXPECTED_CLASSES = {
    "analyzers/ai_review.py": {"AIReviewError": "RuntimeError"},
    "analyzers/dependencies.py": {"DependencyCheckError": "RuntimeError"},
    "analyzers/semgrep.py": {"SemgrepRunnerError": "RuntimeError"},
    "core/exceptions.py": {"ReportError": "RuntimeError"},
    "tui/app.py": {"MCPScannerApp": "App"},
    "tui/screens/comparison.py": {"ComparisonScreen": "Screen"},
    "tui/screens/confirm.py": {"ConfirmScreen": "ModalScreen"},
    "tui/screens/diff_wizard.py": {"DiffPathScreen": "Screen"},
    "tui/screens/export.py": {"ExportScreen": "ModalScreen"},
    "tui/screens/main_menu.py": {"MainMenuScreen": "Screen"},
    "tui/screens/results.py": {"FindingItem": "ListItem", "ResultsScreen": "Screen"},
    "tui/screens/running.py": {"RunningScreen": "Screen"},
    "tui/screens/scan_wizard.py": {"ScanPathScreen": "Screen", "ScanOptionsScreen": "Screen"},
    "tui/screens/settings.py": {"SettingsScreen": "Screen"},
    "tui/screens/setup.py": {"SetupScreen": "Screen"},
    "tui/screens/summary.py": {"ScanSummaryScreen": "Screen"},
    "tui/screens/trust.py": {"IgnoreRuleScreen": "ModalScreen", "TrustScreen": "Screen"},
}
FORBIDDEN_CLASS_NAME = re.compile(r"(Factory|Service|Provider|Registry|Strategy|Abstract|Base|Builder|Singleton)$")
ABSTRACTION_MODULES = {"abc", "typing_extensions"}


def _trees():
    for path in sorted(ROOT.rglob("*.py")):
        yield path.relative_to(ROOT).as_posix(), ast.parse(path.read_text(encoding="utf-8"))


def _classes():
    found = {}
    for relative, tree in _trees():
        classes = {
            node.name: ast.unparse(node.bases[0]) if node.bases else ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        if classes:
            found[relative] = classes
    return found


def test_class_inventory_is_exactly_the_documented_one():
    assert _classes() == EXPECTED_CLASSES


def test_classes_outside_the_tui_are_only_flat_exceptions():
    outside = {path: classes for path, classes in _classes().items() if not path.startswith("tui/")}

    assert all(base == "RuntimeError" for classes in outside.values() for base in classes.values())


def test_tui_classes_only_extend_textual_framework_types():
    inside = {name: base for path, classes in _classes().items() if path.startswith("tui/") for name, base in classes.items()}

    assert set(inside.values()) == {"App", "Screen", "ModalScreen", "ListItem"}


def test_no_factory_service_or_similar_pattern_class_names():
    names = [name for classes in _classes().values() for name in classes]

    assert [name for name in names if FORBIDDEN_CLASS_NAME.search(name)] == []


def test_manager_in_a_class_name_is_only_allowed_for_a_screen():
    # (no class name contains "Manager" any more; the guard stays for future screens)
    offenders = [
        name
        for classes in _classes().values()
        for name, base in classes.items()
        if "Manager" in name and base != "Screen"
    ]

    assert offenders == []


def test_no_abstract_base_classes_protocols_or_abstract_methods():
    bad = []
    for relative, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(alias.name in ABSTRACTION_MODULES for alias in node.names):
                bad.append(f"{relative}: import {[a.name for a in node.names]}")
            if isinstance(node, ast.ImportFrom) and node.module in ABSTRACTION_MODULES:
                bad.append(f"{relative}: from {node.module}")
            if isinstance(node, ast.ImportFrom) and node.module == "typing":
                bad += [f"{relative}: typing.{a.name}" for a in node.names if a.name in {"Protocol", "runtime_checkable"}]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if "abstractmethod" in ast.unparse(decorator):
                        bad.append(f"{relative}: @abstractmethod {node.name}")

    assert bad == []


def test_no_module_level_instances_of_own_classes_used_as_singletons():
    # pattern guard: a module-level `_instance`/`instance`/`_registry` assignment would be a hidden singleton
    bad = []
    for relative, tree in _trees():
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() in {"_instance", "instance", "_registry", "registry"}:
                        bad.append(f"{relative}: {target.id}")

    assert bad == []
