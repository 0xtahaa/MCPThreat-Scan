"""Shared passive contracts: vulnerability categories and severity ranking."""

from __future__ import annotations

VULNERABILITY_CATEGORIES = [
    "Header Leak",
    "Hardcoded Secret",
    "Unscoped Environment Access",
    "Tool Poisoning",
    "Supply Chain",
    "Command Injection",
    "Missing Audit Logging",
    "Capability Mismatch",
    "Typosquatting / Shadow-Server",
]

SEVERITY_ORDER = {"INFO": 0, "WARNING": 1, "ERROR": 2}


def exceeds_severity_threshold(findings: list[dict], threshold: str) -> bool:
    """Return True if any finding's severity is at or above the given threshold."""
    threshold_rank = SEVERITY_ORDER[threshold]
    for finding in findings:
        if SEVERITY_ORDER[finding["severity"]] >= threshold_rank:
            return True
    return False
