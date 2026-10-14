"""Clean benchmark fixture: fictional calendar service with explicit validation."""

from datetime import datetime


def create_event(title, starts_at, calendar_store):
    """Create an event if the timestamp has the expected ISO format."""
    try:
        parsed_start = datetime.fromisoformat(starts_at)
    except ValueError:
        return {"ok": False, "code": "invalid_start_time"}

    if len(title.strip()) < 3:
        return {"ok": False, "code": "title_too_short"}

    event = {
        "title": title.strip(),
        "starts_at": parsed_start.isoformat(),
        "status": "confirmed",
    }
    calendar_store.save(event)
    return {"ok": True, "event": event}
