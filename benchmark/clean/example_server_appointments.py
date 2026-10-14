"""Clean fixture: appointment reminder service. Contains "you must" in docstring as benign API documentation."""


def schedule_reminder(event_id, remind_minutes_before, reminder_store):
    """Schedule a reminder for an existing event.

    You must pass a positive number of minutes, otherwise the reminder is
    rejected before it reaches the store.
    """
    if remind_minutes_before <= 0:
        return {"ok": False, "code": "invalid_lead_time"}

    reminder = {"event_id": event_id, "remind_minutes_before": remind_minutes_before}
    reminder_store.save(reminder)
    return {"ok": True, "reminder": reminder}
