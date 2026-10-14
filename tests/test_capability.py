"""Tests of analyzers.capability (AR-095b): pure logic with an injected signature lookup."""

import pytest

from mcpthreat_scan.analyzers.capability import filter_capability_mismatch_candidates
from mcpthreat_scan.core import orchestrator


def _finding(family="email", rule=None, file="t.py", line=5):
    return {"category": "Capability Mismatch", "file": file, "line": line, "severity": "WARNING",
            "message": "m", "rule_id": rule or f"rules.capability-mismatch-{family}-candidate"}


def _lookup(name, docstring):
    return lambda path, line: {"name": name, "docstring": docstring}


def test_findings_of_other_rules_pass_through_without_lookup():
    def fail(path, line):
        raise AssertionError("lookup must not run")

    other = _finding(rule="rules.command-injection")

    assert filter_capability_mismatch_candidates([other], fail) == [other]


def test_candidate_without_hint_is_kept():
    finding = _finding("email")

    assert filter_capability_mismatch_candidates([finding], _lookup("get_weather", "Zeigt das Wetter")) == [finding]


@pytest.mark.parametrize(
    "family, name, docstring",
    [
        ("email", "send_report", "Sends a report"),   # hint in docstring ("sendet")
        ("email", "notify_user", None),                      # hint in name
        ("network", "fetch_data", "Fetches a URL"),       # hint "url"
        ("network", "SYNC_ALL", "SYNC"),                     # case-insensitive
    ],
)
def test_candidate_with_hint_is_dropped(family, name, docstring):
    assert filter_capability_mismatch_candidates([_finding(family)], _lookup(name, docstring)) == []


def test_underscores_in_name_become_spaces():
    # "e_mail" -> "e mail" does not contain "e-mail" or "email"; "mail" does match.
    assert filter_capability_mismatch_candidates([_finding("email")], _lookup("e_mail_tool", None)) == []


def test_unknown_family_never_counts_as_disclosed():
    finding = _finding("filesystem")

    assert filter_capability_mismatch_candidates([finding], _lookup("send_mail", "sendet e-mail")) == [finding]


def test_unlocatable_function_keeps_the_candidate():
    finding = _finding("email")

    assert filter_capability_mismatch_candidates([finding], lambda path, line: None) == [finding]


def test_lookup_receives_file_and_line_of_the_finding():
    seen = []
    finding = _finding("network", file="a/b.py", line=42)

    filter_capability_mismatch_candidates([finding], lambda p, l: seen.append((p, l)) or None)

    assert seen == [("a/b.py", 42)]


def test_order_and_mixed_input_preserved():
    keep1, drop, other, keep2 = _finding("email", line=1), _finding("email", line=2), \
        _finding(rule="rules.x"), _finding("email", line=4)
    lookup = lambda p, line: {"name": "send_mail" if line == 2 else "get_time", "docstring": None}

    assert filter_capability_mismatch_candidates([keep1, drop, other, keep2], lookup) == [keep1, other, keep2]


def test_orchestrator_wrapper_injects_the_real_signature_lookup(monkeypatch):
    seen = []
    monkeypatch.setattr(
        orchestrator, "extract_handler_signature_at_line",
        lambda p, l: seen.append((p, l)) or {"name": "send_mail", "docstring": None},
    )

    assert orchestrator._filter_capability_mismatch_candidates([_finding("email", file="x.py", line=9)]) == []
    assert seen == [("x.py", 9)]
