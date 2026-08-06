import re
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Deque, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from dedsec.core.passive import PassivePipeline
from dedsec.core.runtime import ScanContext
from dedsec.core.workspace import (
    InsertionPoint,
    RequestRecord,
    ResearchWorkspace,
    ResponseRecord,
    canonical_url,
)


@dataclass
class CrawlConfig:
    max_depth: int = 3
    max_pages: int = 200
    max_links_per_page: int = 500
    max_body_bytes: int = 2 * 1024 * 1024
    timeout: Optional[float] = None
    allow_query_variants: bool = True
    crawl_javascript_candidates: bool = True
    user_agent: str = "DEDSEC/2.0 authorized-research-crawler"


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""
    required: bool = False


@dataclass
class FormSurface:
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    fields: List[FormField] = field(default_factory=list)


class _SurfaceParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.links: List[Tuple[str, str]] = []
        self.forms: List[FormSurface] = []
        self._form: Optional[FormSurface] = None

    @staticmethod
    def _attrs(attrs: Sequence[Tuple[str, Optional[str]]]) -> Dict[str, str]:
        return {str(k).lower(): "" if v is None else str(v) for k, v in attrs}

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        values = self._attrs(attrs)
        tag = tag.lower()
        if tag in {"a", "link"} and values.get("href"):
            self.links.append((tag, values["href"]))
        elif tag in {"script", "iframe", "frame", "img", "source"} and values.get("src"):
            self.links.append((tag, values["src"]))
        elif tag == "form":
            self._form = FormSurface(
                action=values.get("action", ""),
                method=(values.get("method") or "GET").upper(),
                enctype=values.get("enctype") or "application/x-www-form-urlencoded",
            )
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = values.get("name", "").strip()
            if not name:
                return
            field_type = values.get("type") or tag
            value = "" if field_type.lower() == "password" else values.get("value", "")
            self._form.fields.append(
                FormField(
                    name=name,
                    field_type=field_type.lower(),
                    value=value,
                    required="required" in values,
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


_JS_URL_PATTERNS = [
    re.compile(
        r"(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['\"]([^'\"]+)['\"]",
        re.I,
    ),
    re.compile(
        r"\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        re.I,
    ),
]


class CrawlerEngine:
    """Bounded, same-scope crawler that discovers surfaces without submitting forms."""

    SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie"}

    def __init__(
        self,
        context: ScanContext,
        workspace: ResearchWorkspace,
        config: Optional[CrawlConfig] = None,
        passive: Optional[PassivePipeline] = None,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.context = context
        self.workspace = workspace
        self.config = config or CrawlConfig()
        self.passive = passive or PassivePipeline()
        self.default_headers = {
            str(k): str(v)
            for k, v in (default_headers or {}).items()
            if str(k).lower() not in self.SENSITIVE_HEADERS
        }
        self.default_headers.setdefault("User-Agent", self.config.user_agent)
        self.identity_id = getattr(context, "identity_id", "identity-anonymous")
        self._transport = context.get_transport()

    @staticmethod
    def _queue_key(url: str, allow_query_variants: bool) -> str:
        normalized = canonical_url(url)
        if allow_query_variants:
            return normalized
        parsed = urlsplit(normalized)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    @staticmethod
    def _is_http_candidate(raw: str) -> bool:
        lowered = (raw or "").strip().lower()
        if not lowered:
            return False
        return not lowered.startswith(
            ("mailto:", "tel:", "javascript:", "data:", "blob:", "#")
        )

    def _in_scope_url(self, base_url: str, raw: str) -> Optional[str]:
        if not self._is_http_candidate(raw):
            return None
        candidate = canonical_url(urljoin(base_url, raw))
        decision = self.context.scope.check_url(candidate)
        if not decision.allowed:
            return None
        return candidate

    def _record_form(self, page_url: str, form: FormSurface) -> Optional[RequestRecord]:
        action = self._in_scope_url(page_url, form.action or page_url)
        if not action:
            return None
        method = form.method if form.method in {"GET", "POST"} else "GET"
        fields = [(field.name, field.value) for field in form.fields]
        points = [
            InsertionPoint(
                location="query" if method == "GET" else "body",
                name=field.name,
                value=field.value,
                value_type=field.field_type,
                required=field.required,
                source="html-form",
                metadata={"form_action": action, "form_method": method},
            )
            for field in form.fields
        ]
        body: Any = None
        content_type: Optional[str] = None
        request_url = action
        if method == "GET" and fields:
            parsed = urlsplit(action)
            query = list(parse_qsl(parsed.query, keep_blank_values=True)) + fields
            request_url = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
            )
        elif method == "POST":
            body = urlencode(fields)
            content_type = form.enctype or "application/x-www-form-urlencoded"
        request = RequestRecord.build(
            method,
            request_url,
            body=body,
            content_type=content_type,
            identity_id=self.identity_id,
            source="html-form",
            insertion_points=points,
            tags=["form", "not-submitted"],
            metadata={
                "page_url": page_url,
                "has_password_field": any(field.field_type == "password" for field in form.fields),
            },
        )
        self.workspace.add_request(request)
        page_id = self.workspace.add_asset("url", page_url, source="crawler")
        endpoint_id = self.workspace.add_asset(
            "endpoint",
            "%s %s" % (request.method, urlsplit(request.url)._replace(query="", fragment="").geturl()),
            source="html-form",
        )
        self.workspace.add_edge(
            page_id,
            endpoint_id,
            "contains_form",
            {"method": request.method, "submitted": False},
        )
        return request

    def _javascript_candidates(self, base_url: str, text: str) -> List[str]:
        candidates: Set[str] = set()
        for pattern in _JS_URL_PATTERNS:
            for raw in pattern.findall(text or ""):
                candidate = self._in_scope_url(base_url, raw)
                if candidate:
                    candidates.add(candidate)
        return sorted(candidates)

    def crawl(self, start_url: str) -> Dict[str, Any]:
        start = canonical_url(start_url)
        queue: Deque[Tuple[str, int, Optional[str], str]] = deque()
        queue.append((start, 0, None, "seed"))
        queued: Set[str] = {self._queue_key(start, self.config.allow_query_variants)}
        visited: Set[str] = set()
        pages = 0
        transport_failures = 0
        scope_skips = 0
        discovered_forms = 0
        discovered_links = 0
        started = time.monotonic()

        while queue and pages < max(1, int(self.config.max_pages)):
            url, depth, parent_url, source = queue.popleft()
            key = self._queue_key(url, self.config.allow_query_variants)
            if key in visited:
                continue
            visited.add(key)
            if depth > max(0, int(self.config.max_depth)):
                self.workspace.coverage.skip_request("crawl-depth")
                continue

            request = RequestRecord.build(
                "GET",
                url,
                headers=self.default_headers,
                identity_id=self.identity_id,
                source="crawler",
                tags=["crawl", source],
                metadata={"depth": depth, "parent_url": parent_url},
            )
            self.workspace.add_request(request)
            if parent_url:
                parent_id = self.workspace.add_asset("url", parent_url, source="crawler")
                child_id = self.workspace.add_asset("url", url, source="crawler")
                self.workspace.add_edge(parent_id, child_id, "links_to", {"source": source})

            outcome = self._transport.request(
                "GET",
                url,
                timeout=self.config.timeout or self.context.timeout,
                allow_redirects=True,
                headers=self.default_headers,
                cache=True,
            )
            if outcome.response is None:
                transport_failures += 1
                self.workspace.coverage.skip_request(
                    "transport:%s"
                    % (outcome.failure.category if outcome.failure is not None else "unknown"),
                    len(request.insertion_points),
                )
                continue

            response = outcome.response
            raw_body = response.content[: max(0, int(self.config.max_body_bytes))]
            response_record = ResponseRecord.build(
                request.id,
                response.url or url,
                response.status_code,
                headers=dict(response.headers),
                body=raw_body,
                elapsed_seconds=outcome.duration,
                source="crawler",
                metadata={
                    "truncated": len(response.content) > len(raw_body),
                    "attempts": outcome.attempts,
                    "from_cache": outcome.from_cache,
                },
            )
            self.workspace.add_response(response_record)
            pages += 1

            content_type = (response.headers.get("Content-Type") or "").lower()
            text = ""
            if "text/" in content_type or "html" in content_type or "javascript" in content_type:
                text = raw_body.decode(response.encoding or "utf-8", "replace")

            for observation in self.passive.analyze(request, response_record, text):
                self.workspace.add_observation(observation)

            page_id = self.workspace.add_asset(
                "url",
                response_record.url,
                attributes={
                    "status_code": response_record.status_code,
                    "content_type": response_record.content_type,
                },
                source="crawler",
            )
            host = urlsplit(response_record.url).hostname or ""
            host_id = self.workspace.add_asset("host", host, source="crawler")
            self.workspace.add_edge(
                host_id,
                page_id,
                "serves",
                {"status": response_record.status_code},
            )

            if "html" in content_type or "<html" in text[:4096].lower():
                parser = _SurfaceParser()
                try:
                    parser.feed(text)
                except Exception:
                    parser = _SurfaceParser()
                for form in parser.forms:
                    if self._record_form(response_record.url, form) is not None:
                        discovered_forms += 1

                for tag, raw_link in parser.links[: max(1, int(self.config.max_links_per_page))]:
                    candidate = self._in_scope_url(response_record.url, raw_link)
                    if not candidate:
                        scope_skips += 1
                        continue
                    discovered_links += 1
                    candidate_id = self.workspace.add_asset("url", candidate, source="crawler")
                    relation = "loads_script" if tag == "script" else "links_to"
                    self.workspace.add_edge(page_id, candidate_id, relation, {"tag": tag})
                    candidate_key = self._queue_key(candidate, self.config.allow_query_variants)
                    if candidate_key not in queued and depth < self.config.max_depth:
                        queued.add(candidate_key)
                        queue.append((candidate, depth + 1, response_record.url, tag))

            if self.config.crawl_javascript_candidates and (
                "javascript" in content_type or response_record.url.lower().endswith(".js")
            ):
                for candidate in self._javascript_candidates(response_record.url, text):
                    discovered_links += 1
                    candidate_id = self.workspace.add_asset("url", candidate, source="javascript")
                    self.workspace.add_edge(
                        page_id,
                        candidate_id,
                        "references",
                        {"source": "javascript"},
                    )
                    candidate_key = self._queue_key(candidate, self.config.allow_query_variants)
                    if candidate_key not in queued and depth < self.config.max_depth:
                        queued.add(candidate_key)
                        queue.append((candidate, depth + 1, response_record.url, "javascript"))

        return {
            "pages_observed": pages,
            "urls_visited": len(visited),
            "urls_queued": len(queued),
            "forms_discovered": discovered_forms,
            "links_discovered": discovered_links,
            "scope_skips": scope_skips,
            "transport_failures": transport_failures,
            "duration_seconds": round(time.monotonic() - started, 3),
            "limits": {
                "max_depth": self.config.max_depth,
                "max_pages": self.config.max_pages,
                "max_body_bytes": self.config.max_body_bytes,
            },
        }
