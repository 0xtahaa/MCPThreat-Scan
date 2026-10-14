"""JSON rendering of finished scan and diff reports."""

from __future__ import annotations

import json


def render_json(report: dict) -> str:
    """Render report as pretty JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False)
