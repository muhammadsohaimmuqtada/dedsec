import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

from dedsec.core.evidence import EvidenceStore
from dedsec.core.health import TargetHealth
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
    target_health: Optional[TargetHealth] = None
    default_headers: Dict[str, str] = field(default_factory=dict)
    identity_id: str = "identity-anonymous"
    metadata: Dict[str, Any] = field(default_factory=dict)
    _transport: Any = field(default=None, init=False, repr=False)
    _transport_lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        if self.target_health is None:
            self.target_health = TargetHealth(self.domain)
        self.default_headers = {str(k): str(v) for k, v in self.default_headers.items()}

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
        health_failure_threshold: int = 2,
        health_cooldown_seconds: float = 15.0,
        allowed_hosts: Optional[Iterable[str]] = None,
        denied_hosts: Optional[Iterable[str]] = None,
        allowed_ports: Optional[Iterable[int]] = None,
        include_paths: Optional[Iterable[str]] = None,
        exclude_paths: Optional[Iterable[str]] = None,
        default_headers: Optional[Dict[str, str]] = None,
        identity_id: str = "identity-anonymous",
    ) -> "ScanContext":
        evidence = EvidenceStore(artifact_dir=evidence_dir)
        scope = ScopePolicy.from_root(
            domain,
            allowed_hosts=allowed_hosts,
            denied_hosts=denied_hosts,
            allowed_ports=allowed_ports,
            include_subdomains=include_subdomains,
            include_paths=include_paths,
            exclude_paths=exclude_paths,
        )
        return cls(
            scan_id=evidence.scan_id,
            target_url=target_url,
            domain=domain,
            scope=scope,
            evidence=evidence,
            timeout=timeout,
            request_budget=RequestBudget(max_requests=max_requests),
            target_health=TargetHealth(
                domain,
                failure_threshold=health_failure_threshold,
                cooldown_seconds=health_cooldown_seconds,
            ),
            default_headers=dict(default_headers or {}),
            identity_id=identity_id,
        )
