from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, TypedDict, Optional


class Vulnerability(TypedDict, total=False):
    """Subset of the vulnerability fields used for report rendering.

    Additional keys can be present at runtime; they are intentionally omitted
    from the type to keep maintenance surface small. Access only through
    ``get`` in code to remain safe when keys are absent.
    """

    Severity: str
    VulnerabilityID: str
    PkgName: str
    InstalledVersion: str
    FixedVersion: str
    Title: str
    Description: str
    image: str 


@dataclass(slots=True)
class ScanResult:
    """Structured result of scanning a single image.

    Attributes:
        image: Original reference/tag or image id.
        findings: Total vulnerability count discovered.
        sev_counts: Mapping of severity -> count.
        json_path: Path to the JSON artifact produced by Trivy.
        vulnerabilities: Flat list of vulnerabilities (subset of fields).
        containers: Names of containers that use this image (populated post-scan).
    """

    image: str
    findings: int
    sev_counts: Dict[str, int] = field(default_factory=dict)
    json_path: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    containers: List[str] = field(default_factory=list)

    def severity_breakdown(self) -> str:
        """Return a deterministic string used in text & markdown outputs."""
        return ", ".join(f"{k}:{v}" for k, v in sorted(self.sev_counts.items()))


# (filename, path on disk, MIME type)
Attachment = Tuple[str, str, str]

# Convenience alias for report bodies (plain, optional HTML)
ReportBodies = Tuple[str, Optional[str]]

__all__ = [
    "Vulnerability",
    "ScanResult",
    "Attachment",
    "ReportBodies",
]

# Severity ordering (lowest -> highest)
SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_RANK = {v: i for i, v in enumerate(SEVERITY_ORDER)}

def meets_threshold(severity: str, threshold: str) -> bool:
    """Return True if severity is >= threshold according to defined ordering.

    Unknown severities are treated as lowest.
    Inputs are case-insensitive.
    """
    s = severity.upper() if severity else "UNKNOWN"
    t = threshold.upper() if threshold else "LOW"
    return _SEV_RANK.get(s, 0) >= _SEV_RANK.get(t, 0)

__all__.extend(["SEVERITY_ORDER", "meets_threshold"])
