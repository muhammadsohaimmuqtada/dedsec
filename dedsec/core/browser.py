from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from dedsec.core.workspace import RequestRecord, ResearchWorkspace, canonical_url


@dataclass
class BrowserCrawlConfig:
    max_depth: int = 2
    max_pages: int = 50
    max_links_per_page: int = 500
    navigation_timeout_ms: int = 15000
    allow_state_changing_requests: bool = False


class BrowserUnavailable(RuntimeError):
    pass


class BrowserCrawler:
    """Optional Playwright-based SPA discovery with fail-closed routing.

    Browser traffic is scope-filtered before it leaves the browser. Requests
    using non-idempotent methods are recorded as discovered surfaces but are
    aborted by default. Authentication headers are injected only for the exact
    configured target origin, and request cookies are installed as host-scoped
    browser cookies rather than global extra headers.
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie"}

    def __init__(self, context, workspace: ResearchWorkspace, config: Optional[BrowserCrawlConfig] = None):
        self.context = context
        self.workspace = workspace
        self.config = config or BrowserCrawlConfig()
        if self.config.max_depth < 0:
            raise ValueError("Browser max_depth cannot be negative")
        if self.config.max_pages < 1:
            raise ValueError("Browser max_pages must be positive")
        if self.config.max_links_per_page < 1:
            raise ValueError("Browser max_links_per_page must be positive")
        if self.config.navigation_timeout_ms < 1000:
            raise ValueError("Browser navigation_timeout_ms must be at least 1000")

    @staticmethod
    def _endpoint(url: str) -> Tuple[str, str, int]:
        parsed = urlsplit(canonical_url(url))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            raise ValueError("Browser endpoint must be an absolute HTTP(S) URL")
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, int(port)

    @staticmethod
    def _cookie_entries(cookie_header: str, target_url: str) -> List[Dict[str, str]]:
        target = canonical_url(target_url)
        BrowserCrawler._endpoint(target)
        entries: List[Dict[str, str]] = []
        for raw_pair in str(cookie_header or "").split(";"):
            pair = raw_pair.strip()
            if not pair or "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name = name.strip()
            if not name:
                continue
            entries.append({"name": name, "value": value.strip(), "url": target})
        return entries

    def _request_policy(self, url: str, method: str) -> Optional[str]:
        candidate = canonical_url(url)
        if not self.context.scope.check_url(candidate).allowed:
            return "scope"
        normalized_method = str(method or "GET").upper()
        if normalized_method not in self.SAFE_METHODS and not self.config.allow_state_changing_requests:
            return "state-changing-not-executed"
        return None

    def _record_browser_request(self, request, candidate: str, blocked_reason: Optional[str] = None) -> None:
        method = str(getattr(request, "method", None) or "GET").upper()
        tags = ["browser-observed", "not-replayed"]
        if blocked_reason:
            tags.extend(["browser-blocked", blocked_reason])
        content_type = None
        try:
            for key, value in dict(request.headers or {}).items():
                if str(key).lower() == "content-type":
                    content_type = str(value).split(";", 1)[0].strip().lower()
                    break
        except Exception:
            content_type = None
        record = RequestRecord.build(
            method,
            candidate,
            headers={},
            body=None,
            content_type=content_type,
            identity_id=str(getattr(self.context, "identity_id", "identity-anonymous")),
            source="browser",
            tags=tags,
            metadata={
                "resource_type": getattr(request, "resource_type", None),
                "executed": blocked_reason is None,
                "blocked_reason": blocked_reason,
            },
        )
        self.workspace.add_request(record)

    @classmethod
    def _split_auth_headers(cls, headers: Optional[Dict[str, str]]):
        ordinary: Dict[str, str] = {}
        origin_only: Dict[str, str] = {}
        cookie_header = ""
        for raw_name, raw_value in dict(headers or {}).items():
            name = str(raw_name)
            value = str(raw_value)
            lowered = name.lower()
            if lowered == "cookie":
                cookie_header = value
            elif lowered in {"authorization", "proxy-authorization"}:
                origin_only[name] = value
            else:
                ordinary[name] = value
        return ordinary, origin_only, cookie_header

    def crawl(self, start_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, object]:
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise BrowserUnavailable(
                "Playwright is not installed; install DEDSEC with the browser extra"
            ) from exc

        start = canonical_url(start_url)
        if not self.context.scope.check_url(start).allowed:
            raise ValueError("Browser start URL is outside configured scope")
        target_endpoint = self._endpoint(start)
        ordinary_headers, origin_headers, cookie_header = self._split_auth_headers(headers)

        queue: Deque[Tuple[str, int]] = deque([(start, 0)])
        queued: Set[str] = {start}
        visited: Set[str] = set()
        browser_requests: Set[str] = set()
        pages_observed = 0
        scope_blocked = 0
        state_changing_blocked = 0
        navigation_failures = 0

        try:
            with sync_playwright() as playwright:  # pragma: no cover - optional integration
                try:
                    browser = playwright.chromium.launch(headless=True)
                except PlaywrightError as exc:
                    raise BrowserUnavailable(
                        "Playwright Chromium is unavailable; install the browser runtime"
                    ) from exc

                browser_context = None
                try:
                    browser_context = browser.new_context(extra_http_headers=ordinary_headers)
                    if cookie_header:
                        entries = self._cookie_entries(cookie_header, start)
                        if entries:
                            browser_context.add_cookies(entries)

                    def route_request(route):
                        nonlocal scope_blocked, state_changing_blocked
                        request = route.request
                        candidate = canonical_url(request.url)
                        blocked_reason = self._request_policy(candidate, request.method)
                        if blocked_reason == "scope":
                            scope_blocked += 1
                            route.abort()
                            return

                        browser_requests.add(candidate)
                        if blocked_reason:
                            state_changing_blocked += 1
                            self._record_browser_request(request, candidate, blocked_reason)
                            route.abort()
                            return

                        self._record_browser_request(request, candidate)
                        forwarded = dict(request.headers or {})
                        if self._endpoint(candidate) == target_endpoint:
                            forwarded.update(origin_headers)
                        else:
                            for header_name in list(forwarded):
                                if str(header_name).lower() in self.SENSITIVE_HEADERS:
                                    forwarded.pop(header_name, None)
                        route.continue_(headers=forwarded)

                    browser_context.route("**/*", route_request)
                    page = browser_context.new_page()
                    page.set_default_navigation_timeout(int(self.config.navigation_timeout_ms))

                    while queue and pages_observed < self.config.max_pages:
                        current, depth = queue.popleft()
                        if current in visited or depth > self.config.max_depth:
                            continue
                        visited.add(current)
                        try:
                            page.goto(current, wait_until="domcontentloaded")
                        except PlaywrightError:
                            navigation_failures += 1
                            self.workspace.coverage.skip_request("browser-navigation")
                            continue
                        pages_observed += 1
                        current_id = self.workspace.add_asset("url", current, source="browser")
                        try:
                            links = page.eval_on_selector_all(
                                "a[href]",
                                "els => els.map(e => e.href).filter(Boolean)",
                            )
                        except PlaywrightError:
                            links = []
                        for raw in links[: self.config.max_links_per_page]:
                            candidate = canonical_url(urljoin(current, str(raw)))
                            if self._request_policy(candidate, "GET"):
                                continue
                            candidate_id = self.workspace.add_asset("url", candidate, source="browser")
                            self.workspace.add_edge(
                                current_id,
                                candidate_id,
                                "links_to",
                                {"source": "browser"},
                            )
                            if candidate not in queued and depth < self.config.max_depth:
                                queued.add(candidate)
                                queue.append((candidate, depth + 1))
                finally:
                    if browser_context is not None:
                        browser_context.close()
                    browser.close()
        except BrowserUnavailable:
            raise

        return {
            "pages_observed": pages_observed,
            "browser_requests_observed": len(browser_requests),
            "urls_visited": len(visited),
            "scope_requests_blocked_before_send": scope_blocked,
            "state_changing_requests_recorded_not_executed": state_changing_blocked,
            "navigation_failures": navigation_failures,
            "limits": {
                "max_depth": self.config.max_depth,
                "max_pages": self.config.max_pages,
                "max_links_per_page": self.config.max_links_per_page,
                "allow_state_changing_requests": self.config.allow_state_changing_requests,
            },
        }
