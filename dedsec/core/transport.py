import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

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
        # HTTP error statuses remain valid transport responses.
        return self.response is not None and self.failure is None


class TransportEngine:
    """Scoped HTTP transport with exact on-wire budgeting and bounded redirects."""

    RETRYABLE_STATUS = {429, 500, 502, 503, 504}
    RETRYABLE_FAILURES = {"connect_timeout", "read_timeout", "timeout", "connection"}
    REDIRECT_STATUS = {301, 302, 303, 307, 308}
    MAX_REDIRECTS = 5

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
        self.retries = max(0, int(retries))
        self.backoff = max(0.0, float(backoff))
        self._session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=0,
            pool_connections=max(1, pool_connections),
            pool_maxsize=max(1, pool_maxsize),
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._cache: Dict[str, requests.Response] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _stable(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return "bytes:" + hashlib.sha256(value).hexdigest()
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            return repr(value)

    @classmethod
    def _cache_key(
        cls,
        method: str,
        url: str,
        allow_redirects: bool,
        headers: Optional[Dict[str, str]],
        data: Any,
        params: Any,
        json_body: Any,
    ) -> str:
        normalized_headers = sorted(
            (str(key).lower(), str(value)) for key, value in (headers or {}).items()
        )
        raw = "\n".join(
            [
                method.upper(),
                url,
                str(int(allow_redirects)),
                json.dumps(normalized_headers, separators=(",", ":")),
                cls._stable(data),
                cls._stable(params),
                cls._stable(json_body),
            ]
        )
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

    def _sleep_backoff(self, completed_attempt: int) -> None:
        if self.backoff > 0:
            time.sleep(self.backoff * (2 ** max(0, completed_attempt - 1)))

    def _request_one(
        self,
        method: str,
        url: str,
        *,
        timeout: float,
        headers: Optional[Dict[str, str]],
        data: Any,
        params: Any,
        json_body: Any,
    ) -> RequestOutcome:
        max_attempts = 1 + (self.retries if method in {"GET", "HEAD"} else 0)
        started = time.monotonic()
        last_failure = None

        for attempt in range(1, max_attempts + 1):
            if not self.context.request_budget.consume(1):
                return RequestOutcome(
                    None,
                    RequestFailure("budget", "scan request budget exhausted"),
                    time.monotonic() - started,
                    attempt - 1,
                )
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers=headers,
                    data=data,
                    params=params,
                    json=json_body,
                    verify=self.verify_tls,
                )
                if response.status_code in self.RETRYABLE_STATUS and attempt < max_attempts:
                    self._sleep_backoff(attempt)
                    continue
                return RequestOutcome(response, None, time.monotonic() - started, attempt)
            except Exception as exc:
                last_failure = self._classify_exception(exc)
                if last_failure.category in self.RETRYABLE_FAILURES and attempt < max_attempts:
                    self._sleep_backoff(attempt)
                    continue
                return RequestOutcome(None, last_failure, time.monotonic() - started, attempt)

        return RequestOutcome(
            None,
            last_failure or RequestFailure("request", "request failed"),
            time.monotonic() - started,
            max_attempts,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: Optional[float] = None,
        allow_redirects: bool = False,
        headers: Optional[Dict[str, str]] = None,
        data=None,
        params=None,
        json_body=None,
        cache: bool = True,
        enforce_scope: bool = True,
    ) -> RequestOutcome:
        method_upper = method.upper()
        if enforce_scope:
            decision = self.context.scope.check_url(url)
            if not decision.allowed:
                return RequestOutcome(
                    None,
                    RequestFailure("scope", decision.reason),
                    0.0,
                    0,
                )

        key = self._cache_key(
            method_upper,
            url,
            allow_redirects,
            headers,
            data,
            params,
            json_body,
        )
        cacheable = cache and method_upper in {"GET", "HEAD"} and data is None and json_body is None
        if cacheable:
            with self._lock:
                cached = self._cache.get(key)
            if cached is not None:
                return RequestOutcome(cached, None, 0.0, 0, from_cache=True)

        started = time.monotonic()
        total_attempts = 0
        current_url = url
        current_method = method_upper
        current_data = data
        current_json = json_body
        final_response = None

        for redirect_index in range(self.MAX_REDIRECTS + 1):
            if enforce_scope:
                decision = self.context.scope.check_url(current_url)
                if not decision.allowed:
                    return RequestOutcome(
                        final_response,
                        RequestFailure("scope_redirect", decision.reason),
                        time.monotonic() - started,
                        total_attempts,
                    )

            outcome = self._request_one(
                current_method,
                current_url,
                timeout=timeout or self.context.timeout,
                headers=headers,
                data=current_data,
                params=params if redirect_index == 0 else None,
                json_body=current_json,
            )
            total_attempts += outcome.attempts
            if outcome.response is None:
                return RequestOutcome(
                    None,
                    outcome.failure,
                    time.monotonic() - started,
                    total_attempts,
                )
            final_response = outcome.response

            if not allow_redirects or final_response.status_code not in self.REDIRECT_STATUS:
                break
            location = final_response.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current_url, location)
            if enforce_scope:
                decision = self.context.scope.check_url(next_url)
                if not decision.allowed:
                    return RequestOutcome(
                        final_response,
                        RequestFailure("scope_redirect", decision.reason),
                        time.monotonic() - started,
                        total_attempts,
                    )

            if final_response.status_code == 303 or (
                final_response.status_code in {301, 302} and current_method == "POST"
            ):
                current_method = "GET"
                current_data = None
                current_json = None
            current_url = next_url
        else:
            return RequestOutcome(
                final_response,
                RequestFailure("redirect", "maximum redirect hops exceeded"),
                time.monotonic() - started,
                total_attempts,
            )

        if cacheable and final_response is not None:
            with self._lock:
                self._cache[key] = final_response
        return RequestOutcome(
            final_response,
            None,
            time.monotonic() - started,
            total_attempts,
        )

    def close(self) -> None:
        self._session.close()
