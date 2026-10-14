"""Final import graph of the product package (Phase 14, AR-174 and AR-175).

Static AST graph over src/mcpthreat_scan (no product module is imported by the graph checks),
plus one fresh-interpreter import per module to catch order-dependent cycles at runtime. The
exact edge sets are asserted on purpose: a new dependency between packages fails here until it is
reviewed against rules A to I and documented in docs/ARCHITECTURE.md."""

import ast
import os
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
PKG = "mcpthreat_scan"


def _modules():
    found = {}
    for path in sorted((SRC / PKG).rglob("*.py")):
        parts = path.relative_to(SRC).with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        found[".".join(parts)] = path
    return found


MODULES = _modules()


def _graph():
    """(all edges, module-level edges) between internal modules; function-level imports count as lazy."""
    all_edges, top_edges = defaultdict(set), defaultdict(set)
    for name, path in MODULES.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top_nodes = {id(node) for node in tree.body}
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0, "relative imports are not allowed"
                targets = [node.module or ""]
                if node.module == PKG:
                    targets = [f"{PKG}.{alias.name}" for alias in node.names]
            for target in targets:
                if target != PKG and not target.startswith(PKG + "."):
                    continue
                while target not in MODULES and "." in target:
                    target = target.rsplit(".", 1)[0]
                all_edges[name].add(target)
                if id(node) in top_nodes:
                    top_edges[name].add(target)
    return all_edges, top_edges


def _cycles(graph):
    """Strongly connected components with more than one module, or a module importing itself."""
    index, low, stack, on_stack, found, counter = {}, {}, [], set(), [], [0]

    def visit(vertex):
        index[vertex] = low[vertex] = counter[0]
        counter[0] += 1
        stack.append(vertex)
        on_stack.add(vertex)
        for neighbour in graph.get(vertex, ()):
            if neighbour not in index:
                visit(neighbour)
                low[vertex] = min(low[vertex], low[neighbour])
            elif neighbour in on_stack:
                low[vertex] = min(low[vertex], index[neighbour])
        if low[vertex] == index[vertex]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == vertex:
                    break
            if len(component) > 1 or vertex in graph.get(vertex, ()):
                found.append(sorted(component))

    for vertex in sorted(MODULES):
        if vertex not in index:
            visit(vertex)
    return found


def _package(module):
    parts = module.split(".")
    return parts[1] if len(parts) > 1 else "(root)"


def _package_edges(graph):
    edges = defaultdict(set)
    for module, targets in graph.items():
        for target in targets:
            if _package(module) != _package(target):
                edges[_package(module)].add(_package(target))
    return {package: sorted(targets) for package, targets in sorted(edges.items())}


ALL_EDGES, TOP_EDGES = _graph()

# Final allowed package-level directions (docs/ARCHITECTURE.md, "Finaler Import-Graph").
EXPECTED_PACKAGE_EDGES = {
    "cli": ["core", "reporting", "tui"],
    "core": ["analyzers", "diff", "policy"],
    "reporting": ["core"],
    "tui": ["core", "policy"],
}
EXPECTED_LAZY_EDGES = {
    f"{PKG}.cli.main": {f"{PKG}.tui.app"},
    f"{PKG}.tui.screens.running": {f"{PKG}.tui.screens.results"},
}


def test_the_graph_covers_every_product_area():
    assert {_package(m) for m in MODULES} == {
        "(root)", "analyzers", "cli", "core", "diff", "policy", "reporting", "tui",
    }
    assert len(MODULES) >= 36


def test_no_import_cycles_including_function_level_imports():
    assert _cycles(ALL_EDGES) == []


def test_no_import_cycles_at_module_level():
    assert _cycles(TOP_EDGES) == []


def test_package_level_edges_are_exactly_the_documented_final_graph():
    assert _package_edges(ALL_EDGES) == EXPECTED_PACKAGE_EDGES


def test_only_two_lazy_imports_exist_and_both_are_documented():
    lazy = {
        module: targets - TOP_EDGES.get(module, set())
        for module, targets in ALL_EDGES.items()
        if targets - TOP_EDGES.get(module, set())
    }

    assert lazy == EXPECTED_LAZY_EDGES


def test_leaf_packages_import_nothing_from_other_product_packages():
    edges = _package_edges(ALL_EDGES)

    for leaf in ("analyzers", "diff", "policy"):
        assert leaf not in edges, leaf


def test_only_the_orchestrator_combines_analyzers_diff_and_policy():
    importers = {
        module
        for module, targets in ALL_EDGES.items()
        if any(_package(t) in {"analyzers", "diff", "policy"} and _package(module) == "core" for t in targets)
    }

    assert importers == {f"{PKG}.core.orchestrator"}


def test_no_generic_collection_modules_exist_rule_h():
    generic = {"utils", "helpers", "misc", "common"}

    assert sorted(m for m in MODULES if m.rsplit(".", 1)[-1] in generic) == []


def test_core_contains_only_orchestration_contracts_and_exceptions_rule_i():
    core = sorted(m.rsplit(".", 1)[-1] for m in MODULES if _package(m) == "core" and m != f"{PKG}.core")

    assert core == ["exceptions", "models", "orchestrator"]


def _import_in_fresh_interpreter(module):
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", f"import {module}"],
        capture_output=True, text=True, encoding="utf-8",
        env=dict(os.environ, PYTHONPATH=str(SRC), OPENAI_API_KEY=""),
    )
    return module, result.returncode, result.stderr.strip()[-300:]


def test_every_module_imports_on_its_own_in_a_fresh_interpreter():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_import_in_fresh_interpreter, sorted(MODULES)))

    assert [(m, code, err) for m, code, err in results if code != 0] == []
