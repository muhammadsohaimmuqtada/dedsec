from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


@dataclass
class ScopePolicy:
    """Fail-closed target scope policy used by the v2 runtime."""

    root_domain: str
    allowed_hosts: Set[str] = field(default_factory=set)
    denied_hosts: Set[str] = field(default_factory=set)
    allowed_ports: Optional[Set[int]] = None
    allowed_schemes: Set[str] = field(default_factory=lambda: {"http", "https"})
    include_subdomains: bool = True

    def __post_init__(self):
        root = self._normalize_host(self.root_domain)
        if not root:
            raise ValueError("Scope root_domain must be a valid host")
        self.root_domain = root
        self.allowed_hosts = {self._normalize_host(host) for host in self.allowed_hosts if host}
        self.denied_hosts = {self._normalize_host(host) for host in self.denied_hosts if host}
        if self.allowed_ports is not None:
            self.allowed_ports = {int(port) for port in self.allowed_ports}

    @staticmethod
    def _normalize_host(host: str) -> str:
        return (host or "").strip().rstrip(".").lower()

    def _host_matches(self, host: str, pattern: str) -> bool:
        if "*" in pattern:
            return fnmatch(host, pattern)
        return host == pattern

    def _is_host_allowed(self, host: str) -> ScopeDecision:
        normalized = self._normalize_host(host)
        if not normalized:
            return ScopeDecision(False, "missing host")

        if any(self._host_matches(normalized, item) for item in self.denied_hosts):
            return ScopeDecision(False, "host explicitly denied")

        if self.allowed_hosts:
            if any(self._host_matches(normalized, item) for item in self.allowed_hosts):
                return ScopeDecision(True, "host explicitly allowed")
            return ScopeDecision(False, "host not present in allow-list")

        if normalized == self.root_domain:
            return ScopeDecision(True, "root domain")
        if self.include_subdomains and normalized.endswith("." + self.root_domain):
            return ScopeDecision(True, "subdomain of root domain")
        return ScopeDecision(False, "host outside root-domain scope")

    def check_url(self, url: str) -> ScopeDecision:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in self.allowed_schemes:
            return ScopeDecision(False, "scheme outside scope")

        host_decision = self._is_host_allowed(parsed.hostname or "")
        if not host_decision.allowed:
            return host_decision

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
        if self.allowed_ports is not None and port not in self.allowed_ports:
            return ScopeDecision(False, "port outside scope")
        return ScopeDecision(True, host_decision.reason)

    def check_host(self, host: str, port: Optional[int] = None) -> ScopeDecision:
        decision = self._is_host_allowed(host)
        if not decision.allowed:
            return decision
        if port is not None and self.allowed_ports is not None and port not in self.allowed_ports:
            return ScopeDecision(False, "port outside scope")
        return decision

    @classmethod
    def from_root(
        cls,
        root_domain: str,
        allowed_hosts: Optional[Iterable[str]] = None,
        denied_hosts: Optional[Iterable[str]] = None,
        allowed_ports: Optional[Iterable[int]] = None,
        include_subdomains: bool = True,
    ) -> "ScopePolicy":
        return cls(
            root_domain=root_domain,
            allowed_hosts=set(allowed_hosts or []),
            denied_hosts=set(denied_hosts or []),
            allowed_ports=set(allowed_ports) if allowed_ports is not None else None,
            include_subdomains=include_subdomains,
        )
