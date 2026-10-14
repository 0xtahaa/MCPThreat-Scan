"""Clean benchmark fixture: notification service that legitimately discloses its email capability."""

import logging
import smtplib

logger = logging.getLogger(__name__)


@mcp.tool()
def send_reminder_email(recipient, message):
    """Send a reminder email to the given recipient."""
    logger.info("sending reminder email to %s", recipient)
    smtplib.SMTP("mail.example.invalid")
    return {"sent_to": recipient}
