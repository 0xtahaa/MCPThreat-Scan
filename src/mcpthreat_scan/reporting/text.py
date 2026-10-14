"""Human-readable text rendering of finished scan and diff reports."""

from __future__ import annotations


def render_text(report: dict) -> str:
    """Render report as human-readable terminal text grouped by file."""
    lines: list[str] = []

    if not report["findings"]:
        lines.append("No findings.")
    else:
        findings_by_file: dict[str, list[dict]] = {}
        for finding in report["findings"]:
            findings_by_file.setdefault(finding["file"], []).append(finding)

        for file_path in sorted(findings_by_file):
            lines.append(f"{file_path}:")
            for finding in findings_by_file[file_path]:
                # line=None for dependency findings (whole package) and rug-pull diffs.
                if finding["line"] is not None:
                    location = f"Line {finding['line']}"
                elif finding["category"] == "Supply Chain":
                    location = "Package"
                else:
                    location = "no line reference"
                lines.append(
                    f"  {location} [{finding['category']}] "
                    f"{finding['severity']}: {finding['message']}"
                )

    summary = report["summary"]
    lines.append("")
    lines.append(
        f"Summary: {summary['categories_without_finding']} of "
        f"{summary['categories_checked']} OWASP MCP categories without findings."
    )
    if summary["categories_with_finding"]:
        lines.append(f"Categories with findings: {', '.join(summary['categories_with_finding'])}")
    if summary.get("suppressed_count"):
        lines.append(
            f"{summary['suppressed_count']} finding(s) suppressed by .mcpscannerignore."
        )

    return "\n".join(lines)
