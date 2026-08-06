import errno
import socket
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse


class TargetHealth:
    """Process-shareable root-target reachability state.

    The state is deliberately narrow: it models whether the root target is
    reachable at the transport layer. It does not infer application health or
    vulnerability state.
    """

    UNKNOWN = 0
    REACHABLE = 1
    DEGRADED = 2
    UNREACHABLE = 3

    _STATE_NAMES = {
        UNKNOWN: "unknown",
        REACHABLE: "reachable",
        DEGRADED: "degraded",
        UNREACHABLE: "unreachable",
    }
    _FAILURE_CODES = {
        "": 0,
        "connect_timeout": 1,
        "connection": 2,
        "timeout": 3,
        "dns": 4,
        "unreachable": 5,
        "refused": 6,
    }
    _FAILURE_NAMES = {value: key for key, value in _FAILURE_CODES.items()}
    ROOT_FAILURES = {"connect_timeout", "connection", "timeout", "dns", "unreachable", "refused"}

    def __init__(
        self,
        root_domain: str,
        failure_threshold: int = 2,
        cooldown_seconds: float = 15.0,
        shared_state=None,
        shared_failures=None,
        shared_successes=None,
        shared_last_failure=None,
        shared_last_failure_at=None,
        shared_lock=None,
    ):
        self.root_domain = (root_domain or "").strip().rstrip(".").lower()
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds))
        self._state = self.UNKNOWN
        self._failures = 0
        self._successes = 0
        self._last_failure = 0
        self._last_failure_at = 0.0
        self._shared_state = shared_state
        self._shared_failures = shared_failures
        self._shared_successes = shared_successes
        self._shared_last_failure = shared_last_failure
        self._shared_last_failure_at = shared_last_failure_at
        self._lock = shared_lock or threading.RLock()

    @staticmethod
    def _get(container, fallback):
        return container.value if container is not None else fallback

    @property
    def state_code(self) -> int:
        with self._lock:
            return int(self._get(self._shared_state, self._state))

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return int(self._get(self._shared_failures, self._failures))

    @property
    def successes(self) -> int:
        with self._lock:
            return int(self._get(self._shared_successes, self._successes))

    @property
    def last_failure_code(self) -> int:
        with self._lock:
            return int(self._get(self._shared_last_failure, self._last_failure))

    @property
    def last_failure_at(self) -> float:
        with self._lock:
            return float(self._get(self._shared_last_failure_at, self._last_failure_at))

    def _write(self, state=None, failures=None, successes=None, last_failure=None, last_failure_at=None):
        if state is not None:
            if self._shared_state is not None:
                self._shared_state.value = int(state)
            else:
                self._state = int(state)
        if failures is not None:
            if self._shared_failures is not None:
                self._shared_failures.value = int(failures)
            else:
                self._failures = int(failures)
        if successes is not None:
            if self._shared_successes is not None:
                self._shared_successes.value = int(successes)
            else:
                self._successes = int(successes)
        if last_failure is not None:
            if self._shared_last_failure is not None:
                self._shared_last_failure.value = int(last_failure)
            else:
                self._last_failure = int(last_failure)
        if last_failure_at is not None:
            if self._shared_last_failure_at is not None:
                self._shared_last_failure_at.value = float(last_failure_at)
            else:
                self._last_failure_at = float(last_failure_at)

    def record_success(self) -> None:
        with self._lock:
            successes = int(self._get(self._shared_successes, self._successes)) + 1
            self._write(
                state=self.REACHABLE,
                failures=0,
                successes=successes,
                last_failure=0,
                last_failure_at=0.0,
            )

    def record_failure(self, category: str) -> None:
        normalized = category if category in self.ROOT_FAILURES else "connection"
        with self._lock:
            failures = int(self._get(self._shared_failures, self._failures)) + 1
            state = self.UNREACHABLE if failures >= self.failure_threshold else self.DEGRADED
            self._write(
                state=state,
                failures=failures,
                last_failure=self._FAILURE_CODES.get(normalized, self._FAILURE_CODES["connection"]),
                last_failure_at=time.monotonic(),
            )

    def _circuit_open_from_values(self, state: int, last_failure_at: float) -> bool:
        if state != self.UNREACHABLE:
            return False
        if self.cooldown_seconds <= 0:
            return True
        return (time.monotonic() - last_failure_at) < self.cooldown_seconds

    def should_short_circuit(self) -> bool:
        with self._lock:
            state = int(self._get(self._shared_state, self._state))
            last_failure_at = float(self._get(self._shared_last_failure_at, self._last_failure_at))
            return self._circuit_open_from_values(state, last_failure_at)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            state = int(self._get(self._shared_state, self._state))
            failures = int(self._get(self._shared_failures, self._failures))
            successes = int(self._get(self._shared_successes, self._successes))
            failure_code = int(self._get(self._shared_last_failure, self._last_failure))
            last_failure_at = float(self._get(self._shared_last_failure_at, self._last_failure_at))
            return {
                "state": self._STATE_NAMES.get(state, "unknown"),
                "state_code": state,
                "consecutive_failures": failures,
                "successes": successes,
                "last_failure_category": self._FAILURE_NAMES.get(failure_code, ""),
                "circuit_open": self._circuit_open_from_values(state, last_failure_at),
                "failure_threshold": self.failure_threshold,
                "cooldown_seconds": self.cooldown_seconds,
            }

    def sync_from_values(
        self,
        state: int,
        failures: int,
        successes: int,
        last_failure: int,
        last_failure_at: float,
    ) -> None:
        with self._lock:
            self._write(
                state=state,
                failures=failures,
                successes=successes,
                last_failure=last_failure,
                last_failure_at=last_failure_at,
            )


def _classify_socket_error(exc: BaseException) -> str:
    if isinstance(exc, socket.timeout):
        return "connect_timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, OSError):
        if exc.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
            return "unreachable"
        if exc.errno == errno.ECONNREFUSED:
            return "refused"
        if exc.errno == errno.ETIMEDOUT:
            return "connect_timeout"
    return "connection"


def probe_target_connectivity(
    target_url: str,
    health: Optional[TargetHealth] = None,
    timeout: float = 3.0,
    attempts: int = 2,
) -> Dict[str, Any]:
    """Perform a bounded TCP preflight against only the target URL's service.

    This is reachability telemetry, not a vulnerability probe. It performs no
    HTTP request and sends no application payload.
    """
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    timeout = max(0.1, float(timeout))
    attempts = max(1, int(attempts))
    started = time.monotonic()
    resolved_ips = []

    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = sorted({item[4][0] for item in infos})
    except Exception as exc:
        category = _classify_socket_error(exc)
        if health is not None:
            health.record_failure(category)
        return {
            "host": host,
            "scheme": scheme,
            "port": port,
            "dns": "failed",
            "resolved_ips": [],
            "tcp": "unreachable",
            "attempts": 0,
            "failure_category": category,
            "duration_seconds": round(time.monotonic() - started, 3),
        }

    last_category = ""
    attempted = 0
    for _ in range(attempts):
        attempted += 1
        try:
            with socket.create_connection((host, port), timeout=timeout):
                if health is not None:
                    health.record_success()
                return {
                    "host": host,
                    "scheme": scheme,
                    "port": port,
                    "dns": "resolved",
                    "resolved_ips": resolved_ips,
                    "tcp": "reachable",
                    "attempts": attempted,
                    "failure_category": None,
                    "duration_seconds": round(time.monotonic() - started, 3),
                }
        except Exception as exc:
            last_category = _classify_socket_error(exc)
            if health is not None:
                health.record_failure(last_category)

    tcp_state = "filtered_or_timeout" if last_category == "connect_timeout" else "unreachable"
    if last_category == "refused":
        tcp_state = "refused"
    return {
        "host": host,
        "scheme": scheme,
        "port": port,
        "dns": "resolved",
        "resolved_ips": resolved_ips,
        "tcp": tcp_state,
        "attempts": attempted,
        "failure_category": last_category or "connection",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
