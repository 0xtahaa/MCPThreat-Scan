"""Load .mcpscannerignore and filter suppressed findings from a report (P10-1)."""

from __future__ import annotations

from pathlib import Path


def load_ignore_rules(ignore_file: str | Path = ".mcpscannerignore") -> set[tuple[str, str]]:
    """Parse .mcpscannerignore into (path, category) suppression rules. Missing file -> empty set."""
    path = Path(ignore_file)
    if not path.exists():
        return set()

    rules: set[tuple[str, str]] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        file_part, category_part = line.rsplit(":", 1)
        rules.add((file_part.strip(), category_part.strip()))
    return rules


def apply_ignore_rules(findings: list[dict], rules: set[tuple[str, str]]) -> tuple[list[dict], int]:
    """Split findings by (file, category) rules. Returns (kept_findings, suppressed_count)."""
    if not rules:
        return findings, 0

    kept = []
    suppressed_count = 0
    for finding in findings:
        if (finding["file"], finding["category"]) in rules:
            suppressed_count += 1
            continue
        kept.append(finding)
    return kept, suppressed_count


def add_ignore_rule(
    file_path: str, category: str, ignore_file: str | Path = ".mcpscannerignore"
) -> bool:
    """Append "file:category" to the ignore file unless that exact raw line already exists.

    Returns True if a line was appended. The check compares raw lines, not parsed rules (a
    line with different spacing counts as new); a missing file is created."""
    path = Path(ignore_file)
    line = f"{file_path}:{category}"
    existing_lines = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    if line in existing_lines:
        return False

    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return True


def remove_ignore_rule(
    file_path: str, category: str, ignore_file: str | Path = ".mcpscannerignore"
) -> None:
    """Remove one (file, category) rule and rewrite the whole file with the remaining rules sorted.

    Comment and blank lines of the old file are not preserved (behaviour of the TUI ignore manager)."""
    path = Path(ignore_file)
    rules = load_ignore_rules(path)
    rules.discard((file_path, category))
    path.write_text("".join(f"{f}:{c}\n" for f, c in sorted(rules)), encoding="utf-8")
