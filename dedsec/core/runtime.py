import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from dedsec.core.evidence import EvidenceStore
from dedsec.core.scope import ScopePolicy


@dataclass
class RequestBudget:
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
    _transport: Any = field(default=None, init=False, repr=False)
    _transport_lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def get_transport(
        self,
        retries: int = 2,
        backoff: float = 0.4,
        verify_tls: bool = True,
        pool_connections: int = 20,
        pool_maxsize: int = 40,
    ):
        with self._transport_lock:
            if self._transport is None:
                from dedsec.core.transport import TransportEngine

                self._transport = TransportEngine(
                    self,
                    retries=retries,
                    backoff=backoff,
                    verify_tls=verify_tls,
                    pool_connections=pool_connections,
                    pool_maxsize=pool_maxsize,
                )
            return self._transport

    def close(self) -> None:
        with self._transport_lock:
            if self._transport is not None:
                self._transport.close()
                self._transport = None

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
