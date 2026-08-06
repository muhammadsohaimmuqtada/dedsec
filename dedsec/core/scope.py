import posixpath
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Iterable, Optional, Set
from urllib.parse import unquote, urlparse


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


@dataclass
class ScopePolicy:
    """Fail-closed target scope policy for active runtime requests.

    Host, scheme, port, and path rules are enforced centrally. Path rules are
    matched against a conservatively decoded and dot-normalized URL path only;
    query strings do not alter path authorization.
    """

    root_domain: str
    allowed_hosts: Set[str] = field(default_factory=set)
    denied_hosts: Set[str] = field(default_factory=set)
    allowed_ports: Optional[Set[int]] = None
    allowed_schemes: Set[str] = field(default_factory=lambda: {"http", "https"})
    include_subdomains: bool = True
    include_paths: Set[str] = field(default_factory=set)
    exclude_paths: Set[str] = field(default_factory=set)

    def __post_init__(self):
        root = self._normalize_host(self.root_domain)
        if not root:
            raise ValueError("Scope root_domain must be a valid host")
        self.root_domain = root
        self.allowed_hosts = {
            self._normalize_host(host) for host in self.allowed_hosts if self._normalize_host(host)
        }
        self.denied_hosts = {
            self._normalize_host(host) for host in self.denied_hosts if self._normalize_host(host)
        }
        if self.allowed_ports is not None:
            ports = {int(port) for port in self.allowed_ports}
            if any(port < 1 or port > 65535 for port in ports):
                raise ValueError("Scope ports must be between 1 and 65535")
            self.allowed_ports = ports
        self.allowed_schemes = {str(item).lower() for item in self.allowed_schemes}
        if not self.allowed_schemes or not self.allowed_schemes.issubset({"http", "https"}):
            raise ValueError("Scope schemes are restricted to http/https")
        self.include_paths = {str(item).strip() for item in self.include_paths if str(item).strip()}
        self.exclude_paths = {str(item).strip() for item in self.exclude_paths if str(item).strip()}
        for pattern in self.include_paths.union(self.exclude_paths):
            if pattern.startswith("re:"):
                re.compile(pattern[3:])

    @staticmethod
    def _normalize_host(host: str) -> str:
        return (host or "").strip().rstrip(".").lower()

    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        if "*" in pattern:
            return fnmatch(host, pattern)
        return host == pattern

    @staticmethod
    def _normalize_path(path: str) -> str:
        value = path or "/"
        # Decode repeatedly to close differences between policy matching and
        # intermediaries/applications that perform more than one decode pass.
        for _ in range(3):
            decoded = unquote(value)
            if decoded == value:
                break
            value = decoded
        value = value.replace("\\", "/")
        if not value.startswith("/"):
            value = "/" + value
        had_trailing_slash = value.endswith("/")
        normalized = posixpath.normpath(value)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        if had_trailing_slash and normalized != "/" and not normalized.endswith("/"):
            normalized += "/"
        return normalized

    @staticmethod
    def _path_matches(path: str, pattern: str) -> bool:
        if pattern.startswith("re:"):
            return re.search(pattern[3:], path) is not None
        return fnmatch(path, pattern)

    def _check_host(self, host: str) -> ScopeDecision:
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

    def _check_path(self, path: str) -> ScopeDecision:
        normalized = self._normalize_path(path)
        if any(self._path_matches(normalized, item) for item in self.exclude_paths):
            return ScopeDecision(False, "path explicitly denied")
        if self.include_paths and not any(
            self._path_matches(normalized, item) for item in self.include_paths
        ):
            return ScopeDecision(False, "path not present in include rules")
        return ScopeDecision(True, "path allowed")

    def check_url(self, url: str) -> ScopeDecision:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            if scheme not in self.allowed_schemes:
                return ScopeDecision(False, "scheme outside scope")

            host_decision = self._check_host(parsed.hostname or "")
            if not host_decision.allowed:
                return host_decision

            port = parsed.port or (443 if scheme == "https" else 80)
            if port < 1 or port > 65535:
                return ScopeDecision(False, "invalid port")
            if self.allowed_ports is not None and port not in self.allowed_ports:
                return ScopeDecision(False, "port outside scope")

            path_decision = self._check_path(parsed.path or "/")
            if not path_decision.allowed:
                return path_decision
            return ScopeDecision(True, "%s; %s" % (host_decision.reason, path_decision.reason))
        except (TypeError, ValueError):
            return ScopeDecision(False, "invalid URL")

    def check_host(self, host: str, port: Optional[int] = None) -> ScopeDecision:
        decision = self._check_host(host)
        if not decision.allowed:
            return decision
        if port is not None:
            if int(port) < 1 or int(port) > 65535:
                return ScopeDecision(False, "invalid port")
            if self.allowed_ports is not None and int(port) not in self.allowed_ports:
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
        include_paths: Optional[Iterable[str]] = None,
        exclude_paths: Optional[Iterable[str]] = None,
    ) -> "ScopePolicy":
        return cls(
            root_domain=root_domain,
            allowed_hosts=set(allowed_hosts or []),
            denied_hosts=set(denied_hosts or []),
            allowed_ports=set(allowed_ports) if allowed_ports is not None else None,
            include_subdomains=include_subdomains,
            include_paths=set(include_paths or []),
            exclude_paths=set(exclude_paths or []),
        )
