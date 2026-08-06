import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from dedsec.core.evidence import EvidenceStore
from dedsec.core.scope import ScopePolicy


class RequestBudget:
    """Thread/process-safe request budget shared by runtime-aware modules."""

    def __init__(
        self,
        max_requests: Optional[int] = 1000,
        requests_used: int = 0,
        shared_counter=None,
        shared_lock=None,
    ):
        self.max_requests = max_requests
        self._requests_used = int(requests_used)
        self._lock = threading.RLock()
        self._shared_counter = shared_counter
        self._shared_lock = shared_lock

    @property
    def requests_used(self) -> int:
        if self._shared_counter is not None:
            return int(self._shared_counter.value)
        with self._lock:
            return self._requests_used

    @property
    def remaining(self) -> Optional[int]:
        if self.max_requests is None:
            return None
        return max(0, self.max_requests - self.requests_used)

    def set_used(self, value: int) -> None:
        value = max(0, int(value))
        if self._shared_counter is not None:
            lock = self._shared_lock
            if lock is None:
                self._shared_counter.value = value
            else:
                with lock:
                    self._shared_counter.value = value
            return
        with self._lock:
            self._requests_used = value

    def consume(self, amount: int = 1) -> bool:
        """Atomically consume budget and return False when exhausted."""
        amount = max(1, int(amount))
        if self._shared_counter is not None:
            lock = self._shared_lock
            if lock is None:
                current = int(self._shared_counter.value)
                if self.max_requests is not None and current + amount > self.max_requests:
                    return False
                self._shared_counter.value = current + amount
                return True
            with lock:
                current = int(self._shared_counter.value)
                if self.max_requests is not None and current + amount > self.max_requests:
                    return False
                self._shared_counter.value = current + amount
                return True

        with self._lock:
            if self.max_requests is not None and self._requests_used + amount > self.max_requests:
                return False
            self._requests_used += amount
            return True


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
