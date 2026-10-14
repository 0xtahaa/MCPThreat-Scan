"""Capability-mismatch post filter for Semgrep candidates.

Pure text logic: the signature lookup is injected by the caller, so this analyzer
imports no other analyzer and no diff module. Scanned code is never executed.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Keyword hints (case-insensitive) that count as "capability disclosed" per risky family.
# Deliberately small and NOT hardened against deliberate evasion (see rules/capability_mismatch.yaml
# header) - this only needs to catch accidental/undisclosed scope creep, not intentional deception.
_CAPABILITY_HINT_KEYWORDS = {
    "network": [
        "network", "http", "api", "request", "website", "internet", "url", "download",
        "upload", "sync", "synchronize", "external", "remote", "cloud", "web", "fetch",
        "query", "connection", "connect",
    ],
    "email": [
        "email", "e-mail", "mail", "smtp", "send", "sends", "sent", "notify", "notification",
        "message",
    ],
}

_CAPABILITY_MISMATCH_RULE_RE = re.compile(r"capability-mismatch-(\w+)-candidate$")


def filter_capability_mismatch_candidates(
    semgrep_findings: list[dict],
    locate_signature: Callable[[str, int], dict | None],
) -> list[dict]:
    """Drop Capability Mismatch candidates whose name/docstring already hint at the family.

    locate_signature(path, line) returns {"name", "docstring", ...} or None.
    """
    kept_findings = []
    for finding in semgrep_findings:
        match = _CAPABILITY_MISMATCH_RULE_RE.search(finding["rule_id"])
        if match is None:
            kept_findings.append(finding)
            continue

        family = match.group(1)
        signature = locate_signature(finding["file"], finding["line"])
        if signature is None:
            # Could not re-locate the function; keep the candidate rather than silently drop it.
            kept_findings.append(finding)
            continue

        haystack = f"{signature['name'].replace('_', ' ')} {signature['docstring'] or ''}".lower()
        hint_words = _CAPABILITY_HINT_KEYWORDS.get(family, [])
        if any(word in haystack for word in hint_words):
            # Name/docstring already disclose this capability family - not a mismatch.
            continue

        kept_findings.append(finding)
    return kept_findings
