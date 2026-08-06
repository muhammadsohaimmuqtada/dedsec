from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Observation:
    source: str
    kind: str
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class CandidateFinding:
    source: str
    title: str
    reason: str
    severity: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class VerifiedFinding:
    source: str
    title: str
    severity: str
    verification: str
    details: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.evidence_ids:
            raise ValueError("Verified findings require at least one evidence ID")
        self.severity = self.severity.upper()
