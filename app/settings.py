"""Centralized settings for the container vulnerability scanner.

Environment variables:
  SMTP_HOST (str)  - SMTP server host (default: smtp.example.com)
  SMTP_PORT (int)  - SMTP server port (default: 587)
  SMTP_USER (str)  - SMTP username (optional)
  SMTP_PASS (str)  - SMTP password (optional)
  MAIL_FROM (str)  - From address (default: scanner@example.com)
  MAIL_TO (str)    - Comma separated recipient list (default: security@example.com)
  TRIVY_BIN (str)  - Trivy binary name/path (default: trivy)
  TRIVY_ARGS (str) - Extra Trivy arguments
  EXCLUDE_LABEL (str) - Label key=value to exclude containers (default: docktor.ignore=true)
  ONLY_RUNNING (bool) - If true scan only running containers (default: true)
  ATTACH_JSON (bool)  - Attach JSON reports (default: true)
  LOG_LEVEL (str)    - Logging level (default: INFO)
  MIN_NOTIFY_SEVERITY (str) - Minimum severity that triggers email and inclusion in body (default: LOW)
  SCAN_SCOPE (str) - What containers to scan: 'ALL' (default) for all Docker containers visible to the daemon, 'COMPOSE' to restrict to containers that share the same docker-compose project label as this service.
"""
from __future__ import annotations

from dataclasses import dataclass
import os, pathlib, logging
from typing import List

@dataclass(frozen=True)
class Settings:
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_pass: str
    smtp_use_ssl: bool
    mail_from: str
    mail_to: List[str]
    trivy_bin: str
    trivy_args: str
    exclude_label: str
    only_running: bool
    attach_json: bool
    template_dir: pathlib.Path
    log_level: str
    min_notify_severity: str
    scan_scope: str  # 'ALL' or 'COMPOSE'

    @staticmethod
    def load() -> "Settings":
        mail_to_raw = os.getenv("MAIL_TO", "security@example.com")
        mail_to = [x.strip() for x in mail_to_raw.split(",") if x.strip()]
        template_dir = pathlib.Path(__file__).parent / "templates"
        if not template_dir.exists():
            os.makedirs(template_dir)
        return Settings(
            smtp_host=os.getenv("SMTP_HOST", "smtp.example.com"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_user=os.getenv("SMTP_USER", ""),
            smtp_pass=os.getenv("SMTP_PASS", ""),
            smtp_use_ssl=os.getenv("SMTP_USE_SSL", "true").lower() in ["true", "1", "yes"],
            mail_from=os.getenv("MAIL_FROM", "scanner@example.com"),
            mail_to=mail_to,
            trivy_bin=os.getenv("TRIVY_BIN", "trivy"),
            trivy_args=os.getenv(
                "TRIVY_ARGS", "--severity HIGH,CRITICAL --ignore-unfixed --timeout 5m"
            ),
            exclude_label=os.getenv("EXCLUDE_LABEL", "docktor.ignore=true"),
            only_running=os.getenv("ONLY_RUNNING", "true").lower() == "true",
            attach_json=os.getenv("ATTACH_JSON", "true").lower() == "true",
            template_dir=template_dir,
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            min_notify_severity=os.getenv("MIN_NOTIFY_SEVERITY", "LOW").upper(),
            scan_scope=os.getenv("SCAN_SCOPE", "ALL").upper(),
        )

settings = Settings.load()

# Configure logging once
logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
