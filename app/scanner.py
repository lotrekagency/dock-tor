"""Image and container scanning utilities.

This module encapsulates logic for:
  * Enumerating Docker containers (running or all) according to settings.
  * Filtering out containers using exclusion label logic.
  * Scanning unique images with Trivy and collecting vulnerability summaries.
"""

from __future__ import annotations

from typing import Dict, List, Any
import tempfile, os, subprocess, json, logging
import docker
from docker.models.containers import Container

from settings import settings
from domain_types import ScanResult, Vulnerability

logger = logging.getLogger("scanner.scan")


def has_exclude_label(container: Container) -> bool:
    """Return True if the container carries the exclusion label.

    Two mechanisms are supported:
    1. A fixed label key "docktor.ignore" with value "true".
    2. A dynamic label defined by the settings.exclude_label env var in form key=value.
    Failures while reading labels are swallowed and treated as non-excluded.
    """
    try:
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
        return bool(
            labels.get("docktor.ignore", "false").lower() == "true"
            or labels.get(settings.exclude_label.split("=")[0], "false").lower()
            == settings.exclude_label.split("=")[1]
        )
    except Exception:
        return False


def enumerate_containers() -> List[Container]:
    client = docker.from_env()
    containers: List[Container] = client.containers.list(all=not settings.only_running)

    self_id = os.getenv("HOSTNAME", "")
    containers = [c for c in containers if c.id.startswith(self_id) is False]

    if settings.scan_scope != "COMPOSE":
        return containers

    try:
        compose_project: str | None = None
        try:
            this = client.containers.get(self_id)
            compose_project = (
                this.labels.get("com.docker.compose.project")
                if hasattr(this, "labels")
                else this.attrs.get("Config", {})
                .get("Labels", {})
                .get("com.docker.compose.project")
            )
        except Exception:
            compose_project = None
        if not compose_project:
            for c in containers:
                labels = c.attrs.get("Config", {}).get("Labels", {}) or {}
                if labels.get("com.docker.compose.service") == "dock-tor":
                    compose_project = labels.get("com.docker.compose.project")
                    break
        if not compose_project:
            logger.warning(
                "SCAN_SCOPE=COMPOSE set but compose project label could not be determined; scanning all containers instead."
            )
            return containers
        filtered = []
        for c in containers:
            labels = c.attrs.get("Config", {}).get("Labels", {}) or {}
            if labels.get("com.docker.compose.project") == compose_project:
                filtered.append(c)
        return filtered
    except Exception as e:
        logger.exception("Failed applying compose scope filter: %s", e)
        return containers


def scan_image(image_ref: str) -> ScanResult:
    """Scan a single image with Trivy returning a ``ScanResult`` instance."""
    json_fd, json_path = tempfile.mkstemp(prefix="trivy_", suffix=".json")
    os.close(json_fd)
    cmd_json = f'{settings.trivy_bin} image --quiet --format json {settings.trivy_args} "{image_ref}" -o "{json_path}"'
    subprocess.run(cmd_json, shell=True, check=False)
    try:
        with open(json_path, "r") as f:  # type: ignore[assignment]
            data: Dict[str, Any] = json.load(f)
    except Exception:
        data = {}
    findings = 0
    sev_counts: Dict[str, int] = {}
    vulnerabilities: List[Vulnerability] = []
    try:
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                findings += 1
                sev = str(vuln.get("Severity", "UNKNOWN")).upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                sv = Vulnerability(image=image_ref, **vuln)
                vulnerabilities.append(sv)
    except Exception:
        pass
    return ScanResult(
        image=image_ref,
        findings=findings,
        sev_counts=sev_counts,
        json_path=json_path,
        vulnerabilities=vulnerabilities,
    )


def scan_all(containers: List[Container]) -> List[ScanResult]:
    """Deduplicate container images and scan each returning ``ScanResult`` list."""
    image_refs: List[str] = []
    mapping: Dict[str, List[str]] = {}
    for c in containers:
        if has_exclude_label(c):
            continue
        image_ref = c.image.tags[0] if c.image.tags else c.image.id
        image_refs.append(image_ref)
        mapping.setdefault(image_ref, []).append(c.name)
    unique_refs = sorted(set(image_refs))
    if not unique_refs:
        return []
    results: List[ScanResult] = []
    for image_ref in unique_refs:
        logger.info("Scanning image %s", image_ref)
        results.append(scan_image(image_ref))
    # Attach container name mapping to each result for later rendering convenience
    for r in results:
        r.containers = mapping.get(r.image, [])
    return results
