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

# Short remediation advice per category (shown in the TUI and in SARIF rule help). Static text,
# not derived from the scanned code.
REMEDIATION_BY_CATEGORY = {
    "Header Leak": "Do not put request headers into error messages or logs; if headers are needed, filter to non-sensitive ones.",
    "Hardcoded Secret": "Remove the secret from the source, rotate it, and load it from an environment variable or a secret manager.",
    "Unscoped Environment Access": "Read the environment once at server start-up and pass the value on scoped, instead of reading it on every call.",
    "Tool Poisoning": "Review the tool description or output and remove instructions aimed at the AI agent; keep descriptions factual.",
    "Supply Chain": "Upgrade or replace the dependency version named in the finding; the listed advisory IDs describe the fix.",
    "Command Injection": "Do not pass tool input into a shell. Use argument lists without a shell and validate input against an allowlist.",
    "Missing Audit Logging": "Log every tool invocation (tool name, caller, argument summary, outcome) so actions can be audited.",
    "Capability Mismatch": "Make the tool description disclose what the handler really does, or remove the undisclosed capability.",
    "Typosquatting / Shadow-Server": "Check that the server name is intentional; rename it or confirm it does not impersonate a known server.",
}
_DEFAULT_REMEDIATION = "Review this finding manually and decide whether it is a real risk for your server."


def recommendation_for(finding: dict) -> str:
    """Remediation advice for one finding row (by category, with two honest special cases)."""
    category = finding["category"]
    if category == "Scan Coverage":
        return "Not a vulnerability: this file was not fully analyzed. Review it manually."
    if category == "Supply Chain" and finding["severity"] == "INFO":
        return "Install osv-scanner and scan again to enable the npm dependency check."
    return REMEDIATION_BY_CATEGORY.get(category, _DEFAULT_REMEDIATION)


def exceeds_severity_threshold(findings: list[dict], threshold: str) -> bool:
    """Return True if any finding's severity is at or above the given threshold."""
    threshold_rank = SEVERITY_ORDER[threshold]
    for finding in findings:
        if SEVERITY_ORDER[finding["severity"]] >= threshold_rank:
            return True
    return False


def is_scanner_note(finding: dict) -> bool:
    """True for rows that tell about the scan itself (a file or check was skipped), not about a risk.

    They must never be counted as security findings."""
    return finding["category"] == "Scan Coverage" or finding.get("rule_id") == "osv-scanner-missing"
