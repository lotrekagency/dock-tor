"""Email helper utilities."""

from __future__ import annotations

import smtplib, mimetypes, logging
from typing import Sequence, Optional
from domain_types import Attachment
from email.message import EmailMessage
from settings import settings


logger = logging.getLogger("scanner.email")



def send_email_with_attachments(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    mail_from: str,
    mail_to: Sequence[str],
    subject: str,
    body: str,
    attachments: Sequence[Attachment],
    html_body: Optional[str] = None,
) -> None:
    """Send an email with file attachments.

    attachments: Iterable of tuples (filename, path, mime). If mime is an
    empty string it will be guessed from the filename using mimetypes.
    """
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = ", ".join(mail_to)
    msg["Subject"] = subject
    # Plain text part
    msg.set_content(body or "(empty body)")
    # Optional HTML alternative
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    for filename, path, mime in attachments:
        with open(path, "rb") as f:
            data = f.read()
        guessed = mimetypes.guess_type(filename)[0] if not mime else None
        mime_value = mime or (guessed or "application/octet-stream")
        maintype, subtype = mime_value.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP(smtp_host, smtp_port) as s:
        if settings.smtp_use_ssl:
            s.starttls()
        if smtp_user:
            s.login(smtp_user, smtp_pass)
        s.send_message(msg)
    logger.debug("Email with %d attachment(s) sent to %s", len(attachments), ",".join(mail_to))