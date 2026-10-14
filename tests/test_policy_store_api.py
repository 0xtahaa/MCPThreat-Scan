"""Policy functions that replace the TUI's direct file access (AR-141, AR-142).

Each function reproduces the behaviour the TUI screens had before, including its quirks;
every test uses tmp_path, the real ignore file and the real reputation store are never touched."""

import json

import pytest

import mcpthreat_scan.policy.reputation as reputation
from mcpthreat_scan.policy.ignore import add_ignore_rule, load_ignore_rules, remove_ignore_rule
from mcpthreat_scan.policy.reputation import list_reviewed, mark_reviewed, revoke_review


# --- ignore -----------------------------------------------------------------------------


def test_add_ignore_rule_creates_the_file_and_the_rule_is_loadable(tmp_path):
    ignore = tmp_path / ".mcpscannerignore"

    assert add_ignore_rule("srv/a.py", "Header Leak", ignore) is True

    assert ignore.read_text(encoding="utf-8") == "srv/a.py:Header Leak\n"
    assert load_ignore_rules(ignore) == {("srv/a.py", "Header Leak")}


def test_add_ignore_rule_appends_and_skips_an_identical_raw_line(tmp_path):
    ignore = tmp_path / ".mcpscannerignore"
    ignore.write_text("# note\nsrv/a.py:Header Leak\n", encoding="utf-8")

    assert add_ignore_rule("srv/a.py", "Header Leak", ignore) is False
    assert add_ignore_rule("srv/b.py", "Tool Poisoning", ignore) is True

    assert ignore.read_text(encoding="utf-8") == "# note\nsrv/a.py:Header Leak\nsrv/b.py:Tool Poisoning\n"


def test_add_ignore_rule_compares_raw_lines_not_parsed_rules(tmp_path):
    # Pinned quirk of the old results screen: same rule with different spacing is appended again.
    ignore = tmp_path / ".mcpscannerignore"
    ignore.write_text("srv/a.py: Header Leak\n", encoding="utf-8")

    assert add_ignore_rule("srv/a.py", "Header Leak", ignore) is True
    assert ignore.read_text(encoding="utf-8").splitlines() == ["srv/a.py: Header Leak", "srv/a.py:Header Leak"]


def test_add_ignore_rule_keeps_windows_paths_with_a_colon(tmp_path):
    ignore = tmp_path / ".mcpscannerignore"

    add_ignore_rule("C:\\projekte\\server.py", "Tool Poisoning", ignore)

    assert load_ignore_rules(ignore) == {("C:\\projekte\\server.py", "Tool Poisoning")}


def test_add_ignore_rule_glues_onto_a_last_line_without_newline(tmp_path):
    # Pinned quirk: the old code appended blindly, so an unterminated last line is extended.
    ignore = tmp_path / ".mcpscannerignore"
    ignore.write_text("srv/a.py:Header Leak", encoding="utf-8")

    add_ignore_rule("srv/b.py", "Tool Poisoning", ignore)

    assert ignore.read_text(encoding="utf-8") == "srv/a.py:Header Leaksrv/b.py:Tool Poisoning\n"


def test_remove_ignore_rule_rewrites_sorted_and_drops_comments(tmp_path):
    ignore = tmp_path / ".mcpscannerignore"
    ignore.write_text(
        "# comment\nz.py:Tool Poisoning\n\na.py:Header Leak\nm.py:Command Injection\n", encoding="utf-8"
    )

    remove_ignore_rule("m.py", "Command Injection", ignore)

    assert ignore.read_text(encoding="utf-8") == "a.py:Header Leak\nz.py:Tool Poisoning\n"


def test_remove_ignore_rule_handles_windows_paths_and_unknown_rules(tmp_path):
    ignore = tmp_path / ".mcpscannerignore"
    ignore.write_text("C:\\p\\s.py:Tool Poisoning\nb.py:Header Leak\n", encoding="utf-8")

    remove_ignore_rule("not:there.py", "Header Leak", ignore)
    assert load_ignore_rules(ignore) == {("C:\\p\\s.py", "Tool Poisoning"), ("b.py", "Header Leak")}

    remove_ignore_rule("C:\\p\\s.py", "Tool Poisoning", ignore)
    assert load_ignore_rules(ignore) == {("b.py", "Header Leak")}


def test_ignore_default_file_is_resolved_against_the_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    add_ignore_rule("a.py", "Header Leak")

    assert (tmp_path / ".mcpscannerignore").read_text(encoding="utf-8") == "a.py:Header Leak\n"


# --- reputation -------------------------------------------------------------------------


def test_list_reviewed_is_empty_without_a_store(tmp_path):
    assert list_reviewed(tmp_path / "missing.json") == {}


def test_list_reviewed_returns_the_entries_written_by_mark_reviewed(tmp_path):
    store = tmp_path / "rep.json"
    server = tmp_path / "server.py"
    server.write_text("x = 1\n", encoding="utf-8")
    version_hash = mark_reviewed("mein-server", server, store_path=store)

    entries = list_reviewed(store)

    assert list(entries) == ["mein-server"]
    assert entries["mein-server"]["version_hash"] == version_hash
    assert "reviewed_at" in entries["mein-server"]


def test_revoke_review_removes_only_the_named_entry_and_keeps_the_json_format(tmp_path):
    store = tmp_path / "sub" / "rep.json"
    store.parent.mkdir()
    store.write_text(json.dumps({"a": {"reviewed_at": "t1"}, "b": {"reviewed_at": "t2"}}), encoding="utf-8")

    revoke_review("a", store)

    assert store.read_text(encoding="utf-8") == json.dumps({"b": {"reviewed_at": "t2"}}, indent=2, ensure_ascii=False)


def test_revoke_review_of_an_unknown_name_keeps_all_entries(tmp_path):
    store = tmp_path / "rep.json"
    store.write_text(json.dumps({"a": {"reviewed_at": "t1"}}), encoding="utf-8")

    revoke_review("unknown", store)

    assert list_reviewed(store) == {"a": {"reviewed_at": "t1"}}


def test_default_store_path_is_looked_up_at_call_time(tmp_path, monkeypatch):
    store = tmp_path / "patched.json"
    store.write_text(json.dumps({"x": {"reviewed_at": "t"}}), encoding="utf-8")
    monkeypatch.setattr(reputation, "DEFAULT_STORE_PATH", store)

    assert list_reviewed() == {"x": {"reviewed_at": "t"}}
    revoke_review("x")
    assert list_reviewed() == {}


def test_unicode_names_survive_a_revoke_of_another_entry(tmp_path):
    store = tmp_path / "rep.json"
    store.write_text(json.dumps({"Naïve": {"reviewed_at": "t"}, "b": {}}, ensure_ascii=False), encoding="utf-8")

    revoke_review("b", store)

    assert "Naïve" in store.read_text(encoding="utf-8")
