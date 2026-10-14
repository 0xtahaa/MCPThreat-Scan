"""Clean benchmark fixture: fictional in-memory notes service."""

_NOTES = [
    {"id": "n-001", "title": "Release checklist", "tags": ["release", "qa"]},
    {"id": "n-002", "title": "Customer interview notes", "tags": ["research"]},
]


def list_notes(tag=None):
    """Return notes from local memory only."""
    if tag is None:
        return list(_NOTES)
    return [note for note in _NOTES if tag in note["tags"]]


def add_note(title, tags=None):
    """Add a short note after basic validation."""
    if not title or len(title) > 120:
        return {"ok": False, "error": "invalid title"}

    note = {"id": f"n-{len(_NOTES) + 1:03d}", "title": title, "tags": list(tags or [])}
    _NOTES.append(note)
    return {"ok": True, "note": note}
