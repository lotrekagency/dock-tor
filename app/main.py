"""Application entrypoint.

High-level workflow:
    1. Enumerate containers (see `scanner.enumerate_containers`).
    2. Scan and summarize unique images (see `scanner.scan_all`).
    3. Render text + HTML reports (see `reporting.render_reports`).
    4. Build attachments (see `reporting.build_attachments`).
    5. Send email (see `email_utils.send_email_with_attachments`).

Settings: loaded once in `settings.settings`.
"""

from __future__ import annotations

import logging
from typing import List

from settings import settings
from email_utils import send_email_with_attachments
from scanner import enumerate_containers, scan_all
from reporting import render_reports, build_attachments
from domain_types import Attachment, ScanResult, meets_threshold

logger = logging.getLogger("scanner")


def main() -> None:
    """Entrypoint for scanning and reporting.

    Steps:
      * Collect container list.
      * Filter out excluded containers.
      * Deduplicate images and scan each.
      * Build a summary report and dispatch via email.
    """
    containers = enumerate_containers()
    results: List[ScanResult] = scan_all(containers)
    if not results:
        logger.info("No containers to scan.")
        return

    any_trigger = any(
        any(meets_threshold(v.get("Severity", "UNKNOWN"), settings.min_notify_severity) for v in r.vulnerabilities)
        for r in results
    )
    if not any_trigger:
        logger.info(
            "No vulnerabilities meeting threshold %s found; notification suppressed.",
            settings.min_notify_severity,
        )
        return

    body, html_body = render_reports(results)
    attachments: List[Attachment] = build_attachments(results)

    subject = f"[Docker Scan] {len(results)} image(s) scanned (threshold {settings.min_notify_severity})"
    send_email_with_attachments(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_user=settings.smtp_user,
        smtp_pass=settings.smtp_pass,
        mail_from=settings.mail_from,
        mail_to=settings.mail_to,
        subject=subject,
        body=body,
        attachments=attachments,
        html_body=html_body,
    )


if __name__ == "__main__":
    main()
