"""Tests for P11-4: manifest.json vs registered tools in the code."""

import json

import pytest

from mcpthreat_scan.analyzers.manifest import compare_manifest_to_code, load_declared_tools
from mcpthreat_scan.core import orchestrator
from mcpthreat_scan.diff.tool_schema import extract_registered_tool_names


def _write_manifest(directory, tools=None, *, server_type="python", **extra):
    manifest = {"manifest_version": "0.3", "name": "x", "server": {"type": server_type}, **extra}
    if tools is not None:
        manifest["tools"] = [{"name": name} for name in tools]
    path = directory / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _write_server(directory, decorators, filename="server.py"):
    body = "".join(f"{decorator}\ndef {name}():\n    return 1\n\n" for name, decorator in decorators)
    (directory / filename).write_text(body, encoding="utf-8")


# --- load_declared_tools --------------------------------------------------------------------


def test_load_declared_tools_reads_names_and_generated_flag(tmp_path):
    path = _write_manifest(tmp_path, ["a", "b"], tools_generated=True)

    assert load_declared_tools(path) == {
        "tools": {"a", "b"},
        "generated": True,
        "server_type": "python",
    }


def test_load_declared_tools_reads_node_manifests(tmp_path):
    # P12-5c: node servers are comparable now; the type tells the caller to read TS/JS files.
    path = _write_manifest(tmp_path, ["a"], server_type="node")

    assert load_declared_tools(path) == {"tools": {"a"}, "generated": False, "server_type": "node"}


@pytest.mark.parametrize("server_type", ["binary", None])
def test_load_declared_tools_ignores_manifests_of_unreadable_server_types(tmp_path, server_type):
    path = _write_manifest(tmp_path, ["a"], server_type=server_type)

    assert load_declared_tools(path) is None


def test_load_declared_tools_ignores_manifest_without_tools_list(tmp_path):
    assert load_declared_tools(_write_manifest(tmp_path, None)) is None


def test_load_declared_tools_ignores_non_object_json(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("[1, 2]", encoding="utf-8")

    assert load_declared_tools(path) is None


def test_load_declared_tools_raises_on_invalid_json(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_declared_tools(path)


# --- compare_manifest_to_code ---------------------------------------------------------------


def test_compare_flags_undeclared_code_tool_as_warning_and_missing_code_tool_as_info():
    declared = {"tools": {"a", "gone"}, "generated": False}

    rows = compare_manifest_to_code("m.json", declared, {"a", "hidden"})

    assert [(r["severity"], r["category"], r["line"], r["file"]) for r in rows] == [
        ("WARNING", "Supply Chain", None, "m.json"),
        ("INFO", "Supply Chain", None, "m.json"),
    ]
    assert "'hidden'" in rows[0]["message"] and "'gone'" in rows[1]["message"]


def test_compare_is_silent_when_manifest_and_code_match():
    assert compare_manifest_to_code("m.json", {"tools": {"a"}, "generated": False}, {"a"}) == []


def test_compare_does_not_report_undeclared_tools_when_manifest_announces_generated_tools():
    rows = compare_manifest_to_code("m.json", {"tools": {"a"}, "generated": True}, {"a", "extra"})

    assert rows == []


# --- extract_registered_tool_names ----------------------------------------------------------


def test_registered_tool_names_use_explicit_name_and_ignore_undecorated_functions(tmp_path):
    _write_server(
        tmp_path,
        [
            ("plain", "@mcp.tool()"),
            ("bare", "@mcp.tool"),
            ("renamed", '@mcp.tool(name="explicit")'),
            ("positional", '@mcp.tool("first_arg")'),
            ("resource_handler", '@mcp.resource("x://y")'),
            ("undecorated", ""),
        ],
    )

    assert extract_registered_tool_names(tmp_path / "server.py") == {
        "plain", "bare", "explicit", "first_arg",
    }


def test_registered_tool_names_find_async_and_nested_tools(tmp_path):
    (tmp_path / "s.py").write_text(
        "def build():\n    @mcp.tool()\n    async def inner():\n        return 1\n", encoding="utf-8"
    )

    assert extract_registered_tool_names(tmp_path / "s.py") == {"inner"}


# --- _run_manifest_stage --------------------------------------------------------------------


def test_manifest_stage_reports_hidden_tool(tmp_path):
    manifest = _write_manifest(tmp_path, ["a"])
    _write_server(tmp_path, [("a", "@mcp.tool()"), ("b", "@mcp.tool()")])

    rows = orchestrator._run_manifest_stage(tmp_path)

    assert [(r["severity"], r["file"]) for r in rows] == [("WARNING", str(manifest))]
    assert "'b'" in rows[0]["message"]


def test_manifest_stage_yields_nothing_without_manifest_or_for_single_file(tmp_path):
    _write_server(tmp_path, [("a", "@mcp.tool()")])

    assert orchestrator._run_manifest_stage(tmp_path) == []
    assert orchestrator._run_manifest_stage(tmp_path / "server.py") == []


def test_manifest_stage_skips_invalid_manifest_and_unparsable_python(tmp_path):
    (tmp_path / "manifest.json").write_text("{broken", encoding="utf-8")
    assert orchestrator._run_manifest_stage(tmp_path) == []

    _write_manifest(tmp_path, ["a"])
    _write_server(tmp_path, [("a", "@mcp.tool()")])
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00")

    assert orchestrator._run_manifest_stage(tmp_path) == []


def test_manifest_stage_assigns_code_to_nearest_manifest_and_skips_third_party_dirs(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    venv = outer / ".venv"
    for directory in (inner, venv):
        directory.mkdir(parents=True)
    _write_manifest(outer, ["outer_tool"])
    _write_server(outer, [("outer_tool", "@mcp.tool()")])
    _write_manifest(inner, ["inner_tool"])
    _write_server(inner, [("inner_tool", "@mcp.tool()")])
    _write_server(venv, [("vendored", "@mcp.tool()")])

    assert orchestrator._run_manifest_stage(tmp_path) == []


# --- P12-5c: manifests of node servers ------------------------------------------------------


def _write_ts_server(directory, tool_names, filename="server.ts"):
    body = "".join(
        f'server.registerTool("{name}", {{ description: "d", inputSchema: {{}} }}, async () => 1);\n'
        for name in tool_names
    )
    (directory / filename).write_text(body, encoding="utf-8")


def test_manifest_stage_reports_hidden_tool_of_a_node_server(tmp_path):
    manifest = _write_manifest(tmp_path, ["a"], server_type="node")
    _write_ts_server(tmp_path, ["a", "b"])

    rows = orchestrator._run_manifest_stage(tmp_path)

    assert [(r["severity"], r["file"]) for r in rows] == [("WARNING", str(manifest))]
    assert "'b'" in rows[0]["message"]


def test_manifest_stage_is_silent_when_node_manifest_matches_code(tmp_path):
    _write_manifest(tmp_path, ["a", "b"], server_type="node")
    _write_ts_server(tmp_path, ["a", "b"])

    assert orchestrator._run_manifest_stage(tmp_path) == []


def test_manifest_stage_reads_only_ts_js_files_for_node_and_only_py_for_python(tmp_path):
    # A node manifest must not be compared with Python code and vice versa.
    _write_manifest(tmp_path, ["a"], server_type="node")
    _write_ts_server(tmp_path, ["a"])
    _write_server(tmp_path, [("extra", "@mcp.tool()")])

    assert orchestrator._run_manifest_stage(tmp_path) == []


def test_manifest_stage_skips_node_modules_and_typing_files_and_unreadable_files(tmp_path):
    _write_manifest(tmp_path, ["a"], server_type="node")
    _write_ts_server(tmp_path, ["a"])
    vendored = tmp_path / "node_modules" / "dep"
    vendored.mkdir(parents=True)
    _write_ts_server(vendored, ["vendored_tool"], "index.js")
    _write_ts_server(tmp_path, ["typing_only"], "types.d.ts")
    (tmp_path / "dir.ts").mkdir()  # a directory named like a source file must not crash the stage

    assert orchestrator._run_manifest_stage(tmp_path) == []


def test_manifest_stage_node_benchmark_pair():
    hidden = orchestrator._run_manifest_stage(
        orchestrator.Path("benchmark/vulnerable/manifest_hidden_tool_node")
    )
    clean = orchestrator._run_manifest_stage(orchestrator.Path("benchmark/clean/manifest_matching_node"))

    assert [r["severity"] for r in hidden] == ["WARNING"] and "'export_all_notes'" in hidden[0]["message"]
    assert clean == []
