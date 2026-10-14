"""SARIF 2.1.0 rendering of finished scan and diff reports."""

from __future__ import annotations

import json
from pathlib import Path

from mcpthreat_scan.core.models import VULNERABILITY_CATEGORIES


# Category names like "Header Leak" -> stable, URL-safe short IDs like "header-leak".
_CATEGORY_TO_SARIF_RULE_ID = {
    category: category.lower().replace(" ", "-") for category in VULNERABILITY_CATEGORIES
}

# SARIF only knows note/warning/error (no "info").
_SARIF_LEVEL_BY_SEVERITY = {"INFO": "note", "WARNING": "warning", "ERROR": "error"}


def render_sarif(report: dict) -> str:
    """Render report as SARIF 2.1.0 JSON (industry standard for GitHub Code Scanning/CI)."""
    rules = [
        {"id": rule_id, "name": category, "shortDescription": {"text": category}}
        for category, rule_id in _CATEGORY_TO_SARIF_RULE_ID.items()
    ]

    results = []
    for finding in report["findings"]:
        rule_id = _CATEGORY_TO_SARIF_RULE_ID.get(finding["category"], "other")
        physical_location: dict = {
            "artifactLocation": {"uri": Path(finding["file"]).as_posix()}
        }
        if finding["line"] is not None:
            physical_location["region"] = {"startLine": finding["line"]}

        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL_BY_SEVERITY[finding["severity"]],
                "message": {"text": finding["message"]},
                "locations": [{"physicalLocation": physical_location}],
            }
        )

    sarif_report = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpthreat-scan",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_report, indent=2, ensure_ascii=False)
