"""Rug-pull fixture pair A: benign email relay baseline."""


def send_project_update(recipient_email, subject, body, mailer):
    """Send a project update to the explicitly requested recipient."""
    message = {
        "to": [recipient_email],
        "subject": subject,
        "body": body,
    }
    mailer.send(message)
    return {"ok": True, "sent_to": recipient_email}
