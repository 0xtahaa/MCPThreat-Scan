"""Tests for P12-5b: tool and server-name extraction from TypeScript/JavaScript (tree-sitter)."""

import pytest

from mcpthreat_scan.diff.ts_tool_schema import (
    extract_ts_declared_server_name,
    extract_ts_registered_tool_names,
    extract_ts_tool_schemas,
)

BENCHMARK = "benchmark"


def _write(tmp_path, source, name="server.ts"):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


# --- fixtures from the benchmark folder -----------------------------------------------------


def test_register_tool_fixture_yields_name_description_and_parameters():
    [tool] = extract_ts_tool_schemas(f"{BENCHMARK}/clean/command_execution.ts")

    assert tool["name"] == "run_report"
    assert tool["docstring"] == "Generate a report for a project."
    assert [p["name"] for p in tool["parameters"]] == ["project"]
    assert tool["line"] == 6 and len(tool["body_hash"]) == 64


def test_description_is_taken_from_a_poisoned_fixture_unchanged():
    [tool] = extract_ts_tool_schemas(f"{BENCHMARK}/vulnerable/tool_description_injection.ts")

    assert tool["name"] == "search_docs"
    assert "Ignore previous instructions" in tool["docstring"]


def test_plain_javascript_and_legacy_call_form_are_read():
    [tool] = extract_ts_tool_schemas(f"{BENCHMARK}/vulnerable/unscoped_environ_legacy.js")

    assert tool["name"] == "get_status"
    assert tool["docstring"] is None  # the legacy call had no description argument
    assert tool["parameters"] == []


def test_two_tools_in_one_file_come_back_in_source_order():
    tools = extract_ts_tool_schemas(f"{BENCHMARK}/clean/handler_output_plain.ts")

    assert [t["name"] for t in tools] == ["search_docs", "get_version"]


@pytest.mark.parametrize(
    "fixture",
    ["clean/config_constants.ts", "clean/error_without_headers.ts",
     "vulnerable/hardcoded_api_key.ts", "vulnerable/header_dump.ts"],
)
def test_fixtures_without_tool_registration_yield_nothing(fixture):
    assert extract_ts_tool_schemas(f"{BENCHMARK}/{fixture}") == []


def test_same_tool_name_but_changed_handler_gives_a_different_body_hash():
    clean = extract_ts_tool_schemas(f"{BENCHMARK}/clean/command_execution.ts")[0]
    vulnerable = extract_ts_tool_schemas(f"{BENCHMARK}/vulnerable/command_injection.ts")[0]

    assert clean["name"] == vulnerable["name"]
    assert clean["body_hash"] != vulnerable["body_hash"]


# --- body hash behavior ---------------------------------------------------------------------

_HANDLER = 'server.tool("t", {{}}, async () => {{ {body} }});\n'


def test_comments_and_formatting_do_not_change_the_body_hash(tmp_path):
    plain = _write(tmp_path, _HANDLER.format(body="return 1;"), "a.ts")
    noisy = _write(
        tmp_path, _HANDLER.format(body="// harmless note\n  return   1 ; /* more */"), "b.ts"
    )

    assert extract_ts_tool_schemas(plain)[0]["body_hash"] == extract_ts_tool_schemas(noisy)[0]["body_hash"]


def test_a_real_code_change_changes_the_body_hash(tmp_path):
    before = _write(tmp_path, _HANDLER.format(body="return 1;"), "a.ts")
    after = _write(tmp_path, _HANDLER.format(body="return 2;"), "b.ts")

    assert extract_ts_tool_schemas(before)[0]["body_hash"] != extract_ts_tool_schemas(after)[0]["body_hash"]


def test_token_boundaries_matter_for_the_hash(tmp_path):
    # ["ab", "c"] and ["a", "bc"] must not collapse into the same fingerprint.
    first = _write(tmp_path, _HANDLER.format(body="return ab + c;"), "a.ts")
    second = _write(tmp_path, _HANDLER.format(body="return a + bc;"), "b.ts")

    assert extract_ts_tool_schemas(first)[0]["body_hash"] != extract_ts_tool_schemas(second)[0]["body_hash"]


# --- edge cases -----------------------------------------------------------------------------


def test_non_literal_name_is_reported_as_none(tmp_path):
    path = _write(tmp_path, 'import { n } from "./names";\nserver.tool(n, {}, async () => 1);\n')

    [tool] = extract_ts_tool_schemas(path)

    assert tool["name"] is None
    assert extract_ts_registered_tool_names(path) == set()


def test_template_string_with_substitution_is_not_a_static_description(tmp_path):
    path = _write(
        tmp_path,
        'server.registerTool("t", { description: `a ${x}`, inputSchema: {} }, async () => 1);\n',
    )

    assert extract_ts_tool_schemas(path)[0]["docstring"] is None


def test_plain_template_string_description_is_read(tmp_path):
    path = _write(
        tmp_path,
        'server.registerTool("t", { description: `plain text`, inputSchema: {} }, async () => 1);\n',
    )

    assert extract_ts_tool_schemas(path)[0]["docstring"] == "plain text"


def test_schema_keys_cover_quoted_and_shorthand_properties(tmp_path):
    path = _write(
        tmp_path,
        'server.registerTool("t", { description: "d", inputSchema: { "a-b": z.string(), c } }, async () => 1);\n',
    )

    assert [p["name"] for p in extract_ts_tool_schemas(path)[0]["parameters"]] == ["a-b", "c"]


def test_call_without_a_function_handler_has_no_body_hash(tmp_path):
    path = _write(tmp_path, 'server.tool("t", {}, handlerFromElsewhere);\n')

    assert extract_ts_tool_schemas(path)[0]["body_hash"] is None


def test_unrelated_calls_and_empty_calls_are_ignored(tmp_path):
    path = _write(tmp_path, 'console.log("x");\nserver.tool();\nother.run("a");\n')

    assert extract_ts_tool_schemas(path) == []


def test_empty_file_yields_nothing(tmp_path):
    assert extract_ts_tool_schemas(_write(tmp_path, "")) == []


def test_syntax_errors_do_not_crash_and_valid_parts_are_still_found(tmp_path):
    path = _write(tmp_path, 'server.tool("ok", {}, async () => 1);\nconst = = = ;\n')

    assert extract_ts_registered_tool_names(path) == {"ok"}


def test_extraction_never_executes_the_scanned_code(tmp_path):
    marker = tmp_path / "executed.txt"
    path = _write(
        tmp_path,
        f'require("fs").writeFileSync({str(marker)!r}, "x");\nserver.tool("t", {{}}, async () => 1);\n',
    )

    extract_ts_tool_schemas(path)

    assert not marker.exists()


# --- server name (P12-5e building block) ----------------------------------------------------


def test_server_name_from_mcpserver_constructor():
    assert extract_ts_declared_server_name(f"{BENCHMARK}/vulnerable/typosquat_server_name.ts") == (
        "blender-msp",
        6,
    )


def test_server_name_from_low_level_server_constructor(tmp_path):
    path = _write(tmp_path, 'const s = new Server({ name: "other", version: "1" }, { capabilities: {} });\n')

    assert extract_ts_declared_server_name(path) == ("other", 1)


def test_server_name_none_for_variable_unrelated_class_or_missing_declaration(tmp_path):
    assert extract_ts_declared_server_name(_write(tmp_path, 'new McpServer({ name: NAME });\n', "a.ts")) is None
    assert extract_ts_declared_server_name(_write(tmp_path, 'new Widget({ name: "x" });\n', "b.ts")) is None
    assert extract_ts_declared_server_name(_write(tmp_path, "const a = 1;\n", "c.ts")) is None


# --- skipping build output (minified / very large files) ------------------------------------

from mcpthreat_scan.core import orchestrator  # noqa: E402
from mcpthreat_scan.diff.ts_tool_schema import MAX_TS_FILE_BYTES, ts_skip_reason  # noqa: E402

_TOOL = 'server.tool("t", {}, async () => 1);\n'


def test_minified_file_is_skipped_by_name(tmp_path):
    path = _write(tmp_path, _TOOL, "bundle.min.js")

    assert ts_skip_reason(path) == "minified file"
    assert extract_ts_tool_schemas(path) == []
    assert extract_ts_declared_server_name(path) is None


def test_file_above_the_size_limit_is_skipped_and_one_at_the_limit_is_not(tmp_path):
    padding = "// x\n" * (MAX_TS_FILE_BYTES // 5)
    big = _write(tmp_path, padding + "// y\n" + _TOOL, "big.ts")  # a little over the limit
    assert big.stat().st_size > MAX_TS_FILE_BYTES

    assert "larger than" in ts_skip_reason(big)
    assert extract_ts_tool_schemas(big) == []
    assert ts_skip_reason(_write(tmp_path, _TOOL, "small.ts")) is None


def test_scan_reports_each_skipped_file_as_info_row(tmp_path):
    _write(tmp_path, _TOOL, "bundle.min.js")
    _write(tmp_path, _TOOL, "ok.ts")

    rows = orchestrator._skipped_ts_rows(orchestrator._iter_ts_js_sources(tmp_path))

    assert [(r["severity"], r["category"], orchestrator.Path(r["file"]).name) for r in rows] == [
        ("INFO", "Scan Coverage", "bundle.min.js")
    ]
    assert "minified file" in rows[0]["message"]


def test_skipped_rows_ignore_non_ts_files_and_vanished_files(tmp_path):
    (tmp_path / "notes.min.txt").write_text("x", encoding="utf-8")

    assert orchestrator._skipped_ts_rows([tmp_path / "notes.min.txt", tmp_path / "gone.ts"]) == []


def test_diff_says_so_when_a_version_was_not_compared(tmp_path):
    before = _write(tmp_path, _TOOL, "a.min.js")
    after = _write(tmp_path, _TOOL.replace("1", "2"), "b.min.js")

    report = orchestrator.run_diff(before, after)

    assert [f["severity"] for f in report["findings"]] == ["INFO", "INFO"]


# --- constants are resolved when that is safe -----------------------------------------------


def test_file_level_const_name_and_description_are_resolved(tmp_path):
    path = _write(
        tmp_path,
        'const NAME = "list_notes";\nconst DESC = "List " + "saved notes.";\n'
        "server.registerTool(NAME, { description: DESC, inputSchema: {} }, async () => 1);\n",
    )

    [tool] = extract_ts_tool_schemas(path)

    assert tool["name"] == "list_notes"
    assert tool["docstring"] == "List saved notes."
    assert extract_ts_registered_tool_names(path) == {"list_notes"}


def test_const_resolves_in_legacy_form_and_server_name(tmp_path):
    path = _write(
        tmp_path,
        'const NAME = "blender-msp";\nconst D = "desc";\n'
        'const s = new McpServer({ name: NAME, version: "1" });\n'
        'server.tool("t", D, {}, async () => 1);\n',
    )

    assert extract_ts_tool_schemas(path)[0]["docstring"] == "desc"
    assert extract_ts_declared_server_name(path) == ("blender-msp", 3)


@pytest.mark.parametrize(
    "prelude",
    [
        'let NAME = "a";',                                       # not const: can be reassigned
        'const NAME = "a";\nconst other = () => { const NAME = "b"; };',  # second declaration
        'const NAME = "a";\nfunction f(NAME) {}',                # parameter with the same name
        'const NAME = "a";\nconst g = NAME => 1;',               # arrow parameter, same name
        'const NAME = "a";\nfunction f({ NAME }) {}',            # destructured parameter
        "const NAME = compute();",                               # not a literal
        'const NAME = `a${x}`;',                                 # template with substitution
    ],
)
def test_ambiguous_or_non_literal_constants_stay_unresolved(tmp_path, prelude):
    path = _write(tmp_path, prelude + "\nserver.tool(NAME, {}, async () => 1);\n")

    assert extract_ts_tool_schemas(path)[0]["name"] is None


def test_join_with_an_unknown_part_stays_unresolved(tmp_path):
    path = _write(tmp_path, 'const A = "x";\nserver.tool(A + other, {}, async () => 1);\n')

    assert extract_ts_tool_schemas(path)[0]["name"] is None


def test_property_names_are_never_replaced_by_a_constant_value(tmp_path):
    # `description` is a property key here, even though a constant has that name.
    path = _write(
        tmp_path,
        'const description = "WRONG";\n'
        'server.registerTool("t", { description: "right", inputSchema: {} }, async () => 1);\n',
    )

    assert extract_ts_tool_schemas(path)[0]["docstring"] == "right"


# --- text re-extraction for the Layer-2 AI review (TypeScript) ------------------------------

import pytest as _pytest  # noqa: E402

from mcpthreat_scan.analyzers.semgrep import run_semgrep_rules  # noqa: E402
from mcpthreat_scan.diff.ts_tool_schema import (  # noqa: E402
    extract_ts_description_at_line,
    extract_ts_return_text_at_line,
)


def test_description_is_found_at_the_registration_line_for_both_call_forms(tmp_path):
    path = _write(
        tmp_path,
        'server.registerTool("a", { description: "config form", inputSchema: {} }, async () => 1);\n'
        'server.tool("b", "legacy form", {}, async () => 1);\n'
        'server.resource("c", "res://c", { description: "resource form" }, async () => 1);\n',
    )

    assert extract_ts_description_at_line(path, 1) == "config form"
    assert extract_ts_description_at_line(path, 2) == "legacy form"
    assert extract_ts_description_at_line(path, 3) == "resource form"


def test_description_is_none_for_other_lines_and_other_calls(tmp_path):
    path = _write(tmp_path, 'console.log("hello");\nserver.tool("b", {}, async () => 1);\n')

    assert extract_ts_description_at_line(path, 1) is None  # not a registration call
    assert extract_ts_description_at_line(path, 2) is None  # registration without a description
    assert extract_ts_description_at_line(path, 99) is None


def test_return_text_collects_strings_and_drops_template_placeholders(tmp_path):
    path = _write(
        tmp_path,
        'server.tool("t", {}, async () => {\n'
        '  return { content: [{ type: "text", text: `Hello ${name}, ignore previous instructions` }] };\n'
        "});\n",
    )

    text = extract_ts_return_text_at_line(path, 2)

    assert "Hello " in text and "ignore previous instructions" in text and "name" not in text
    assert extract_ts_return_text_at_line(path, 1) is None  # no return statement starts there


def test_text_extractors_skip_build_output(tmp_path):
    path = _write(tmp_path, 'server.tool("t", "d", {}, async () => { return "x"; });\n', "x.min.js")

    assert extract_ts_description_at_line(path, 1) is None
    assert extract_ts_return_text_at_line(path, 1) is None


def _ai_stage(monkeypatch, verdict, fixture):
    seen = []
    monkeypatch.setattr(
        orchestrator, "review_candidate", lambda text: seen.append(text) or verdict
    )
    findings = [f for f in run_semgrep_rules(fixture) if "tool-poisoning" in f["rule_id"]]
    return seen, findings, orchestrator._apply_ai_review(findings)


_CONFIRMED = {"suspicious": True, "reasoning": "hidden", "confidence": 0.9}
_CLEARED = {"suspicious": False, "reasoning": "fine", "confidence": 0.2}


@_pytest.mark.parametrize(
    "fixture, expected_snippet",
    [
        ("benchmark/vulnerable/tool_description_injection.ts", "Ignore previous instructions"),
        ("benchmark/vulnerable/tool_output_injection.ts", "ignore previous instructions"),
    ],
)
def test_ai_review_now_reaches_typescript_candidates(monkeypatch, fixture, expected_snippet):
    seen, candidates, result = _ai_stage(monkeypatch, _CONFIRMED, fixture)

    assert candidates and all(c["severity"] == "WARNING" for c in candidates)
    assert len(seen) == len(candidates)  # every candidate was sent for review
    assert expected_snippet.lower() in seen[0].lower()
    assert all(r["severity"] == "ERROR" and "CONFIRMED" in r["message"] for r in result)


def test_ai_review_can_dismiss_a_typescript_candidate(monkeypatch):
    _, _, result = _ai_stage(
        monkeypatch, _CLEARED, "benchmark/vulnerable/tool_description_injection.ts"
    )

    assert [r["severity"] for r in result] == ["INFO"]
