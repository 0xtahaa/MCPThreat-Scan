"""Tests for P4-2: rug-pull detection via schema and body hashing.

Covers tool additions/removals, parameter/docstring changes, and hidden behavior."""

from mcpthreat_scan.diff.rugpull import diff_tool_schema_files, diff_tool_schemas

RUGPULL_DIR = "benchmark/rugpull"


def test_schema_change_pair_detects_added_parameter_and_docstring_change():
    findings = diff_tool_schema_files(
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
        f"{RUGPULL_DIR}/example_search_schema_v2.py",
    )

    changes = {finding["change"] for finding in findings}
    assert "parameters_changed" in changes
    assert "docstring_changed" in changes
    assert "behavior_changed_hidden" not in changes

    param_finding = next(f for f in findings if f["change"] == "parameters_changed")
    assert {"parameter": "include_private", "change": "added"} in param_finding["details"]


def test_hidden_bcc_pair_detects_behavior_change_via_body_hash():
    findings = diff_tool_schema_files(
        f"{RUGPULL_DIR}/example_email_bcc_v1.py",
        f"{RUGPULL_DIR}/example_email_bcc_v2.py",
    )

    changes = {finding["change"] for finding in findings}
    assert changes == {"behavior_changed_hidden"}


def test_no_diff_between_identical_versions():
    findings = diff_tool_schema_files(
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
        f"{RUGPULL_DIR}/example_search_schema_v1.py",
    )

    assert findings == []


def test_added_removed_tools_and_modified_parameter_keep_change_order():
    before_param = {"name": "mode", "kind": "positional", "default": None}
    after_param = {"name": "mode", "kind": "keyword_only", "default": "'safe'"}
    before = [
        {"name": "retired", "parameters": [], "docstring": None, "body_hash": "0" * 64},
        {
            "name": "shared",
            "parameters": [before_param],
            "docstring": None,
            "body_hash": "0" * 64,
        },
    ]
    after = [
        {"name": "fresh", "parameters": [], "docstring": None, "body_hash": "0" * 64},
        {
            "name": "shared",
            "parameters": [after_param],
            "docstring": None,
            "body_hash": "1" * 64,
        },
    ]

    assert diff_tool_schemas(before, after) == [
        {"tool": "retired", "change": "tool_removed"},
        {"tool": "fresh", "change": "tool_added"},
        {
            "tool": "shared",
            "change": "parameters_changed",
            "details": [
                {
                    "parameter": "mode",
                    "change": "modified",
                    "before": before_param,
                    "after": after_param,
                }
            ],
        },
    ]


# --- P12-5d: TypeScript/JavaScript pairs ----------------------------------------------------


def test_ts_hidden_bcc_pair_detects_behavior_change_via_body_hash():
    findings = diff_tool_schema_files(
        f"{RUGPULL_DIR}/example_notes_bcc_v1.ts", f"{RUGPULL_DIR}/example_notes_bcc_v2.ts"
    )

    assert [(f["tool"], f["change"]) for f in findings] == [
        ("send_project_update", "behavior_changed_hidden")
    ]


def test_ts_schema_change_pair_detects_added_parameter_and_changed_description():
    findings = diff_tool_schema_files(
        f"{RUGPULL_DIR}/example_schema_v1.ts", f"{RUGPULL_DIR}/example_schema_v2.ts"
    )

    changes = {finding["change"] for finding in findings}
    assert changes == {"parameters_changed", "docstring_changed"}
    param_finding = next(f for f in findings if f["change"] == "parameters_changed")
    assert {"parameter": "includePrivate", "change": "added"} in param_finding["details"]


def test_ts_identical_versions_give_no_findings():
    path = f"{RUGPULL_DIR}/example_notes_bcc_v1.ts"

    assert diff_tool_schema_files(path, path) == []


def test_ts_comment_or_format_only_change_is_not_reported(tmp_path):
    before = tmp_path / "a.ts"
    after = tmp_path / "b.ts"
    before.write_text('server.tool("t", {}, async () => { return 1; });\n', encoding="utf-8")
    after.write_text('server.tool("t", {},\n  async () => {\n    // note\n    return 1;\n  });\n', encoding="utf-8")

    assert diff_tool_schema_files(before, after) == []


def test_ts_added_and_removed_tools_are_reported(tmp_path):
    before = tmp_path / "a.js"
    after = tmp_path / "b.js"
    before.write_text('server.tool("old", {}, async () => 1);\n', encoding="utf-8")
    after.write_text('server.tool("new", {}, async () => 1);\n', encoding="utf-8")

    findings = diff_tool_schema_files(before, after)

    assert sorted((f["tool"], f["change"]) for f in findings) == [
        ("new", "tool_added"), ("old", "tool_removed"),
    ]


def test_ts_tools_with_non_literal_names_are_left_out_of_the_comparison(tmp_path):
    before = tmp_path / "a.ts"
    after = tmp_path / "b.ts"
    before.write_text('server.tool(NAME, {}, async () => 1);\n', encoding="utf-8")
    after.write_text('server.tool(NAME, {}, async () => 2);\n', encoding="utf-8")

    assert diff_tool_schema_files(before, after) == []
