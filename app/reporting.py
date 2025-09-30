"""Reporting and rendering utilities.

Provides functions to render text/HTML reports from scan results and to
construct email attachments list.
"""

from __future__ import annotations

from typing import List
import datetime, logging, base64
import pathlib
from settings import settings
from domain_types import (
    ScanResult,
    Vulnerability,
    Attachment,
    ReportBodies,
    meets_threshold,
    SEVERITY_ORDER,
)
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("scanner.reporting")


def _aggregate_vulns(results: List[ScanResult]) -> List[Vulnerability]:
    """Flatten and aggregate all vulnerabilities from scan results (unfiltered)."""
    return [v for r in results for v in r.vulnerabilities]


def group_vulns_by_image_and_severity(
    results: List[ScanResult],
) -> list[dict]:
    """Group vulnerabilities by image and severity level."""
    
    rev_severity_order = list(reversed(SEVERITY_ORDER))
    all_vulns = _aggregate_vulns(results)
    filtered_vulns = [
        v
        for v in all_vulns
        if meets_threshold(v.get("Severity", "UNKNOWN"), settings.min_notify_severity)
    ]
    grouped: dict[str, dict[str, list[Vulnerability]]] = {}
    for r in results:
        grouped[r.image] = {sev: [] for sev in rev_severity_order}
    for v in filtered_vulns:
        img = v.get("image") or "<unknown>"
        if img not in grouped:
            grouped[img] = {sev: [] for sev in rev_severity_order}
        sev = v.get("Severity", "UNKNOWN").upper()
        if sev not in grouped[img]:
            grouped[img][sev] = []
        grouped[img][sev].append(v)

    grouped_compact: list[dict] = []
    for image, sev_map in grouped.items():
        ordered = [
            {"severity": sev, "items": sev_map[sev]}
            for sev in rev_severity_order
            if sev in sev_map and sev_map[sev]
        ]
        grouped_compact.append({"image": image, "severities": ordered})
    return grouped_compact


def render_reports(results: List[ScanResult]) -> ReportBodies:
    """Render text and HTML bodies using Jinja2 templates if available.

    Returns (text_body, html_body). If templates or Jinja2 missing -> html_body None.
    """
    generated_at = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
        + "Z"
    )
    env = Environment(
        loader=FileSystemLoader(str(settings.template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Attempt to load logo as base64 data URI (optional)
    logo_path = pathlib.Path(__file__).parent / "static" / "docktor-logo.png"
    logo_data_uri: str | None = None
    try:
        if logo_path.exists():
            b = logo_path.read_bytes()
            enc = base64.b64encode(b).decode("ascii")
            logo_data_uri = f"data:image/png;base64,{enc}"
    except Exception:
        logo_data_uri = None

    context = {
        "results": [
            {
                "image": r.image,
                "findings": r.findings,
                "sev_counts": r.sev_counts,
                "binds": r.containers,
            }
            for r in results
        ],
        "grouped_vulnerabilities": group_vulns_by_image_and_severity(results),
        "severity_order": SEVERITY_ORDER,
        "threshold": settings.min_notify_severity,
        "generated_at": generated_at,
        "logo_data_uri": logo_data_uri,
    }
    text_template = env.get_template(f"report.txt.j2")
    html_template = env.get_template(f"report.html.j2")
    return text_template.render(**context), html_template.render(**context)


def build_attachments(results: List[ScanResult]) -> List[Attachment]:
    """Create list of (filename, path, mime) for report attachments.

    Always includes a per-image Markdown report. Optionally includes JSON if
    settings.attach_json is True.
    """
    attachments: List[Attachment] = []

    env = Environment(
        loader=FileSystemLoader(str(settings.template_dir)),
        autoescape=select_autoescape([]),  # markdown not auto-escaped
        trim_blocks=True,
        lstrip_blocks=True,
    )

    for r in results:
        image_safe = r.image.replace("/", "_").replace(":", "_")
        md_path = pathlib.Path(r.json_path).with_suffix("")
        md_path = md_path.parent / f"report_{image_safe}.md"

        threshold = settings.min_notify_severity
        ordered_vulns = sorted(
            r.vulnerabilities,
            key=lambda v: - SEVERITY_ORDER.index(v.get("Severity", "UNKNOWN").upper())
            if v.get("Severity", "UNKNOWN").upper() in SEVERITY_ORDER
            else - len(SEVERITY_ORDER),
        )

        rendered: str | None = None
        tpl = env.get_template("report_image.md.j2")
        rendered = tpl.render(
            image=r.image,
            binds=r.containers,
            findings=r.findings,
            sev_counts=r.sev_counts,
            vulnerabilities=ordered_vulns,
            threshold=threshold,
            generated_at=datetime.datetime.utcnow().isoformat() + "Z",
        )
        md_path.write_text(rendered, encoding="utf-8")
        attachments.append((f"report_{image_safe}.md", str(md_path), "text/markdown"))

        if settings.attach_json:
            attachments.append(
                (
                    f"trivy_{image_safe}.json",
                    r.json_path,
                    "application/json",
                )
            )
    return attachments
