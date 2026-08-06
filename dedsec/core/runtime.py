from dataclasses import dataclass, field
from typing import Dict, Optional

from dedsec.core.evidence import EvidenceStore
from dedsec.core.scope import ScopePolicy


@dataclass
class RequestBudget:
    """Thread-safe-enough scan budget; mutations are coordinated by the transport lock."""

    max_requests: Optional[int] = 1000
    requests_used: int = 0

    @property
    def remaining(self) -> Optional[int]:
        if self.max_requests is None:
            return None
        return max(0, self.max_requests - self.requests_used)


@dataclass
class ScanContext:
    scan_id: str
    target_url: str
    domain: str
    scope: ScopePolicy
    evidence: EvidenceStore
    timeout: int = 10
    request_budget: RequestBudget = field(default_factory=RequestBudget)
    metadata: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        target_url: str,
        domain: str,
        timeout: int = 10,
        evidence_dir: Optional[str] = None,
        max_requests: Optional[int] = 1000,
        include_subdomains: bool = True,
    ) -> "ScanContext":
        evidence = EvidenceStore(artifact_dir=evidence_dir)
        scope = ScopePolicy.from_root(domain, include_subdomains=include_subdomains)
        return cls(
            scan_id=evidence.scan_id,
            target_url=target_url,
            domain=domain,
            scope=scope,
            evidence=evidence,
            timeout=timeout,
            request_budget=RequestBudget(max_requests=max_requests),
        )
