import threading
import time
from dataclasses import dataclass
from typing import Optional


TRANSIENT = "transient"
PERMANENT = "permanent"
TIMEOUT = "timeout"

_TRANSIENT_MARKERS = (
    "temporar",
    "timeout",
    "timed out",
    "connection reset",
    "connection aborted",
    "connection refused",
    "remote end closed",
    "name resolution",
    "429",
    "502",
    "503",
    "504",
)
_TIMEOUT_MARKERS = ("timeout", "timed out", "deadline exceeded")


def classify_failure(error: Optional[str]) -> str:
    text = (error or "").strip().lower()
    if any(marker in text for marker in _TIMEOUT_MARKERS):
        return TIMEOUT
    if any(marker in text for marker in _TRANSIENT_MARKERS):
        return TRANSIENT
    return PERMANENT


@dataclass(frozen=True)
class RetryPolicy:
    retries: int = 1
    base_backoff: float = 0.5
    max_backoff: float = 2.0

    @property
    def max_attempts(self) -> int:
        return max(1, self.retries + 1)

    def should_retry(self, attempt: int, failure_class: str) -> bool:
        return attempt < self.max_attempts and failure_class in (TRANSIENT, TIMEOUT)

    def delay_for(self, attempt: int) -> float:
        if self.base_backoff <= 0:
            return 0.0
        return min(self.max_backoff, self.base_backoff * (2 ** max(0, attempt - 1)))


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, cooldown: float = 30.0):
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown = max(0.0, cooldown)
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if time.monotonic() - self._opened_at >= self.cooldown:
                self._failures = 0
                self._opened_at = None
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold and self._opened_at is None:
                self._opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        return not self.allow()
