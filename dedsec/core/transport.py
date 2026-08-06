import hashlib
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

if TYPE_CHECKING:
    from dedsec.core.runtime import ScanContext


@dataclass(frozen=True)
class RequestFailure:
    category: str
    message: str


@dataclass
class RequestOutcome:
    response: Optional[requests.Response]
    failure: Optional[RequestFailure]
    duration: float
    attempts: int
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return self.response is not None and self.failure is None


class TransportEngine:
    """Shared HTTP transport for runtime-aware target requests."""

    def __init__(
        self,
        context: "ScanContext",
        retries: int = 2,
        backoff: float = 0.4,
        verify_tls: bool = True,
        pool_connections: int = 20,
        pool_maxsize: int = 40,
    ):
        self.context = context
        self.verify_tls = verify_tls
        self._session = requests.Session()
        retry = Retry(
            total=max(0, retries),
            connect=max(0, retries),
            read=max(0, retries),
            status=max(0, retries),
            backoff_factor=max(0.0, backoff),
            status_forcelist={429, 500, 502, 503, 504},
            allowed_methods={"GET", "HEAD"},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=max(1, pool_connections),
            pool_maxsize=max(1, pool_maxsize),
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._cache: Dict[str, requests.Response] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _cache_key(method: str, url: str, allow_redirects: bool) -> str:
        raw = "%s\n%s\n%s" % (method.upper(), url, int(allow_redirects))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _classify_exception(exc: Exception) -> RequestFailure:
        if isinstance(exc, requests.exceptions.SSLError):
            return RequestFailure("tls", str(exc))
        if isinstance(exc, requests.exceptions.ConnectTimeout):
            return RequestFailure("connect_timeout", str(exc))
        if isinstance(exc, requests.exceptions.ReadTimeout):
            return RequestFailure("read_timeout", str(exc))
        if isinstance(exc, requests.exceptions.Timeout):
            return RequestFailure("timeout", str(exc))
        if isinstance(exc, requests.exceptions.ConnectionError):
            return RequestFailure("connection", str(exc))
        if isinstance(exc, requests.exceptions.InvalidURL):
            return RequestFailure("invalid_url", str(exc))
        return RequestFailure("request", str(exc))

    def _consume_budget(self) -> Optional[RequestFailure]:
        with self._lock:
            budget = self.context.request_budget
            if budget.max_requests is not None and budget.requests_used >= budget.max_requests:
                return RequestFailure("budget", "scan request budget exhausted")
            budget.requests_used += 1
        return None

    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: Optional[float] = None,
        allow_redirects: bool = False,
        headers: Optional[Dict[str, str]] = None,
        data=None,
        cache: bool = True,
        enforce_scope: bool = True,
    ) -> RequestOutcome:
        if enforce_scope:
            decision = self.context.scope.check_url(url)
            if not decision.allowed:
                return RequestOutcome(
                    response=None,
                    failure=RequestFailure("scope", decision.reason),
                    duration=0.0,
                    attempts=0,
                )

        method_upper = method.upper()
        cache_key = self._cache_key(method_upper, url, allow_redirects)
        if cache and method_upper in {"GET", "HEAD"}:
            with self._lock:
                cached = self._cache.get(cache_key)
            if cached is not None:
                return RequestOutcome(cached, None, 0.0, 0, from_cache=True)

        budget_failure = self._consume_budget()
        if budget_failure:
            return RequestOutcome(None, budget_failure, 0.0, 0)

        started = time.monotonic()
        try:
            response = self._session.request(
                method_upper,
                url,
                timeout=timeout or self.context.timeout,
                allow_redirects=allow_redirects,
                headers=headers,
                data=data,
                verify=self.verify_tls,
            )
            duration = time.monotonic() - started
            if cache and method_upper in {"GET", "HEAD"}:
                with self._lock:
                    self._cache[cache_key] = response
            return RequestOutcome(response, None, duration, 1)
        except Exception as exc:
            return RequestOutcome(
                response=None,
                failure=self._classify_exception(exc),
                duration=time.monotonic() - started,
                attempts=1,
            )

    def close(self) -> None:
        self._session.close()
