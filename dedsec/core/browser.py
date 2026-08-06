from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set, Tuple
from urllib.parse import urljoin

from dedsec.core.workspace import RequestRecord, ResearchWorkspace, canonical_url


@dataclass
class BrowserCrawlConfig:
    max_depth: int = 2
    max_pages: int = 50
    navigation_timeout_ms: int = 15000


class BrowserUnavailable(RuntimeError):
    pass


class BrowserCrawler:
    """Optional Playwright-based SPA discovery.

    This crawler only performs bounded page navigations and observes browser
    requests. It does not submit forms, click mutation controls, bypass access
    controls, or attempt anti-bot evasion.
    """

    def __init__(self, context, workspace: ResearchWorkspace, config: Optional[BrowserCrawlConfig] = None):
        self.context = context
        self.workspace = workspace
        self.config = config or BrowserCrawlConfig()

    def crawl(self, start_url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, object]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise BrowserUnavailable(
                "Playwright is not installed; install DEDSEC with the browser extra"
            ) from exc

        queue: Deque[Tuple[str, int]] = deque([(canonical_url(start_url), 0)])
        queued: Set[str] = {canonical_url(start_url)}
        visited: Set[str] = set()
        browser_requests: Set[str] = set()
        pages_observed = 0

        with sync_playwright() as playwright:  # pragma: no cover - optional integration
            browser = playwright.chromium.launch(headless=True)
            browser_context = browser.new_context(extra_http_headers=dict(headers or {}))
            page = browser_context.new_page()
            page.set_default_navigation_timeout(max(1000, int(self.config.navigation_timeout_ms)))

            def on_request(request):
                candidate = canonical_url(request.url)
                if not self.context.scope.check_url(candidate).allowed:
                    return
                browser_requests.add(candidate)
                record = RequestRecord.build(
                    request.method,
                    candidate,
                    headers={},
                    source="browser",
                    tags=["browser-observed", "not-replayed"],
                    metadata={"resource_type": request.resource_type},
                )
                self.workspace.add_request(record)

            page.on("request", on_request)
            while queue and pages_observed < max(1, int(self.config.max_pages)):
                current, depth = queue.popleft()
                if current in visited or depth > self.config.max_depth:
                    continue
                visited.add(current)
                try:
                    page.goto(current, wait_until="domcontentloaded")
                except Exception:
                    self.workspace.coverage.skip_request("browser-navigation")
                    continue
                pages_observed += 1
                current_id = self.workspace.add_asset("url", current, source="browser")
                try:
                    links = page.eval_on_selector_all(
                        "a[href]",
                        "els => els.map(e => e.href).filter(Boolean)",
                    )
                except Exception:
                    links = []
                for raw in links[:1000]:
                    candidate = canonical_url(urljoin(current, str(raw)))
                    if not self.context.scope.check_url(candidate).allowed:
                        continue
                    candidate_id = self.workspace.add_asset("url", candidate, source="browser")
                    self.workspace.add_edge(current_id, candidate_id, "links_to", {"source": "browser"})
                    if candidate not in queued and depth < self.config.max_depth:
                        queued.add(candidate)
                        queue.append((candidate, depth + 1))
            browser_context.close()
            browser.close()

        return {
            "pages_observed": pages_observed,
            "browser_requests_observed": len(browser_requests),
            "urls_visited": len(visited),
            "limits": {
                "max_depth": self.config.max_depth,
                "max_pages": self.config.max_pages,
            },
        }
