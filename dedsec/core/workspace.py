import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:24]
    return "%s-%s" % (prefix, digest)


def canonical_url(url: str) -> str:
    parsed = urlsplit((url or "").strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if not scheme or not host:
        return (url or "").strip()
    port = parsed.port
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    authority = host if port in (None, default_port) else "%s:%d" % (host, port)
    path = parsed.path or "/"
    return urlunsplit((scheme, authority, path, parsed.query, ""))


def _flatten_json(value: Any, prefix: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key in sorted(value):
            name = "%s.%s" % (prefix, key) if prefix else str(key)
            for item in _flatten_json(value[key], name):
                yield item
    elif isinstance(value, list):
        for index, item_value in enumerate(value):
            name = "%s[%d]" % (prefix, index)
            for item in _flatten_json(item_value, name):
                yield item
    else:
        yield prefix, value


@dataclass
class AssetNode:
    id: str
    kind: str
    key: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)


@dataclass
class AssetEdge:
    id: str
    source_id: str
    target_id: str
    relation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InsertionPoint:
    location: str
    name: str
    value: Any = None
    value_type: str = "string"
    required: bool = False
    source: str = "discovered"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return stable_id(
            "ip",
            {
                "location": self.location,
                "name": self.name,
                "source": self.source,
                "metadata": self.metadata,
            },
        )


@dataclass
class IdentityContext:
    id: str
    label: str = "anonymous"
    kind: str = "anonymous"
    role: Optional[str] = None
    tenant: Optional[str] = None
    authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def anonymous(cls) -> "IdentityContext":
        return cls(id="identity-anonymous")

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _point_logical_key(point: InsertionPoint) -> Tuple[str, str]:
    return str(point.location).lower(), str(point.name)


def merge_insertion_points(
    inferred: Sequence[InsertionPoint],
    explicit: Optional[Sequence[InsertionPoint]] = None,
) -> List[InsertionPoint]:
    """Merge input surfaces without allowing explicit metadata to hide inference.

    A logical input is keyed by location and name. Generic inference is loaded
    first; richer explicit schema/crawler metadata replaces only the matching
    logical input. Other inferred inputs remain present.
    """
    merged: Dict[Tuple[str, str], InsertionPoint] = {}
    for point in inferred:
        merged[_point_logical_key(point)] = point
    for point in explicit or []:
        merged[_point_logical_key(point)] = point
    return [merged[key] for key in sorted(merged)]


@dataclass
class RequestRecord:
    id: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None
    content_type: Optional[str] = None
    identity_id: str = "identity-anonymous"
    source: str = "discovered"
    insertion_points: List[InsertionPoint] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
        content_type: Optional[str] = None,
        identity_id: str = "identity-anonymous",
        source: str = "discovered",
        insertion_points: Optional[Sequence[InsertionPoint]] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "RequestRecord":
        normalized_url = canonical_url(url)
        normalized_method = (method or "GET").upper()
        inferred = infer_insertion_points(
            normalized_method,
            normalized_url,
            headers=headers,
            body=body,
            content_type=content_type,
            source=source,
        )
        points = merge_insertion_points(inferred, insertion_points)
        body_shape = body
        if isinstance(body, (dict, list)):
            body_shape = _stable_json(body)
        request_id = stable_id(
            "req",
            {
                "method": normalized_method,
                "url": normalized_url,
                "body": body_shape,
                "content_type": content_type,
                "identity_id": identity_id,
            },
        )
        return cls(
            id=request_id,
            method=normalized_method,
            url=normalized_url,
            headers=dict(headers or {}),
            body=body,
            content_type=content_type,
            identity_id=identity_id,
            source=source,
            insertion_points=points,
            tags=sorted(set(tags or [])),
            metadata=dict(metadata or {}),
        )

    def public_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["insertion_points"] = [asdict(item) for item in self.insertion_points]
        return data


@dataclass
class ResponseRecord:
    id: str
    request_id: str
    url: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    body_sha256: Optional[str] = None
    body_length: int = 0
    elapsed_seconds: float = 0.0
    source: str = "crawler"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        request_id: str,
        url: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        elapsed_seconds: float = 0.0,
        source: str = "crawler",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ResponseRecord":
        raw = body or b""
        response_id = stable_id(
            "resp",
            {"request_id": request_id, "url": canonical_url(url), "status": int(status_code)},
        )
        normalized_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        content_type = normalized_headers.get("Content-Type") or normalized_headers.get("content-type")
        return cls(
            id=response_id,
            request_id=request_id,
            url=canonical_url(url),
            status_code=int(status_code),
            headers=normalized_headers,
            content_type=content_type,
            body_sha256=hashlib.sha256(raw).hexdigest() if raw else None,
            body_length=len(raw),
            elapsed_seconds=round(float(elapsed_seconds), 6),
            source=source,
            metadata=dict(metadata or {}),
        )


@dataclass
class Observation:
    id: str
    category: str
    title: str
    classification: str = "observation"
    severity: str = "INFO"
    confidence: str = "observed"
    asset_id: Optional[str] = None
    request_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    source: str = "passive"

    @classmethod
    def build(
        cls,
        category: str,
        title: str,
        classification: str = "observation",
        severity: str = "INFO",
        confidence: str = "observed",
        asset_id: Optional[str] = None,
        request_id: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        source: str = "passive",
    ) -> "Observation":
        payload = {
            "category": category,
            "title": title,
            "asset_id": asset_id,
            "request_id": request_id,
            "source": source,
            "evidence": evidence or {},
        }
        return cls(
            id=stable_id("obs", payload),
            category=category,
            title=title,
            classification=classification,
            severity=severity.upper(),
            confidence=confidence,
            asset_id=asset_id,
            request_id=request_id,
            evidence=dict(evidence or {}),
            source=source,
        )


@dataclass
class CoverageTracker:
    requests_discovered: int = 0
    requests_observed: int = 0
    requests_audited: int = 0
    requests_skipped: int = 0
    insertion_points_discovered: int = 0
    insertion_points_audited: int = 0
    insertion_points_skipped: int = 0
    skipped_reasons: Dict[str, int] = field(default_factory=dict)

    def discover_request(self, insertion_points: int = 0) -> None:
        self.requests_discovered += 1
        self.insertion_points_discovered += max(0, int(insertion_points))

    def observe_request(self) -> None:
        self.requests_observed += 1

    def audit_request(self, insertion_points: int = 0) -> None:
        self.requests_audited += 1
        self.insertion_points_audited += max(0, int(insertion_points))

    def skip_request(self, reason: str, insertion_points: int = 0) -> None:
        self.requests_skipped += 1
        self.insertion_points_skipped += max(0, int(insertion_points))
        key = reason or "unspecified"
        self.skipped_reasons[key] = self.skipped_reasons.get(key, 0) + 1

    def snapshot(self) -> Dict[str, Any]:
        request_coverage = 0.0
        if self.requests_discovered:
            request_coverage = self.requests_audited / float(self.requests_discovered)
        insertion_coverage = 0.0
        if self.insertion_points_discovered:
            insertion_coverage = self.insertion_points_audited / float(
                self.insertion_points_discovered
            )
        data = asdict(self)
        data["request_audit_coverage"] = round(request_coverage, 4)
        data["insertion_point_audit_coverage"] = round(insertion_coverage, 4)
        return data


class ResearchWorkspace:
    """Canonical cross-module knowledge model for one DEDSEC scan."""

    def __init__(self, scan_id: str, target_url: str, domain: str):
        self.scan_id = scan_id
        self.target_url = canonical_url(target_url)
        self.domain = (domain or "").lower().rstrip(".")
        self.assets: Dict[str, AssetNode] = {}
        self.edges: Dict[str, AssetEdge] = {}
        self.requests: Dict[str, RequestRecord] = {}
        self.responses: Dict[str, ResponseRecord] = {}
        self.observations: Dict[str, Observation] = {}
        self.identities: Dict[str, IdentityContext] = {
            "identity-anonymous": IdentityContext.anonymous()
        }
        self.coverage = CoverageTracker()
        self.metadata: Dict[str, Any] = {}
        domain_id = self.add_asset("domain", self.domain, source="target")
        url_id = self.add_asset("url", self.target_url, source="target")
        self.add_edge(domain_id, url_id, "serves", {"source": "target"})

    @staticmethod
    def _normalize_asset_key(kind: str, key: str) -> str:
        if kind in {"domain", "host"}:
            return (key or "").lower().rstrip(".")
        if kind in {"url", "endpoint"}:
            return canonical_url(key)
        return str(key)

    def add_asset(
        self,
        kind: str,
        key: str,
        attributes: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
    ) -> str:
        normalized_kind = (kind or "asset").lower()
        normalized_key = self._normalize_asset_key(normalized_kind, key)
        asset_id = stable_id("asset", {"kind": normalized_kind, "key": normalized_key})
        existing = self.assets.get(asset_id)
        if existing is None:
            existing = AssetNode(
                id=asset_id,
                kind=normalized_kind,
                key=normalized_key,
                attributes=dict(attributes or {}),
                sources=[],
            )
            self.assets[asset_id] = existing
        elif attributes:
            existing.attributes.update(attributes)
        if source and source not in existing.sources:
            existing.sources.append(source)
            existing.sources.sort()
        return asset_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        edge_id = stable_id(
            "edge",
            {"source": source_id, "target": target_id, "relation": relation},
        )
        current = self.edges.get(edge_id)
        if current is None:
            current = AssetEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                relation=relation,
                metadata=dict(metadata or {}),
            )
            self.edges[edge_id] = current
        elif metadata:
            current.metadata.update(metadata)
        return edge_id

    def add_identity(self, identity: IdentityContext) -> str:
        self.identities[identity.id] = identity
        self.add_asset(
            "identity",
            identity.id,
            attributes={
                "label": identity.label,
                "kind": identity.kind,
                "role": identity.role,
                "tenant": identity.tenant,
                "authenticated": identity.authenticated,
            },
            source="identity",
        )
        return identity.id

    def add_request(self, request: RequestRecord) -> str:
        is_new = request.id not in self.requests
        self.requests[request.id] = request
        endpoint_id = self.add_asset(
            "endpoint",
            request.url,
            attributes={"method": request.method, "content_type": request.content_type},
            source=request.source,
        )
        url_id = self.add_asset("url", request.url, source=request.source)
        self.add_edge(url_id, endpoint_id, "supports_request", {"method": request.method})
        if is_new:
            self.coverage.discover_request(len(request.insertion_points))
        return request.id

    def add_response(self, response: ResponseRecord) -> str:
        self.responses[response.id] = response
        self.coverage.observe_request()
        return response.id

    def add_observation(self, observation: Observation) -> str:
        self.observations[observation.id] = observation
        return observation.id

    def merge_snapshot(self, snapshot: Dict[str, Any]) -> None:
        for raw in snapshot.get("assets", []):
            node = AssetNode(**raw)
            existing = self.assets.get(node.id)
            if existing is None:
                self.assets[node.id] = node
            else:
                existing.attributes.update(node.attributes)
                existing.sources = sorted(set(existing.sources + node.sources))
        for raw in snapshot.get("edges", []):
            edge = AssetEdge(**raw)
            self.edges[edge.id] = edge
        for raw in snapshot.get("requests", []):
            points = [InsertionPoint(**item) for item in raw.get("insertion_points", [])]
            request_raw = dict(raw)
            request_raw["insertion_points"] = points
            request = RequestRecord(**request_raw)
            self.requests[request.id] = request
        for raw in snapshot.get("responses", []):
            response = ResponseRecord(**raw)
            self.responses[response.id] = response
        for raw in snapshot.get("observations", []):
            observation = Observation(**raw)
            self.observations[observation.id] = observation
        for raw in snapshot.get("identities", []):
            identity = IdentityContext(**raw)
            self.identities[identity.id] = identity
        coverage = snapshot.get("coverage") or {}
        for key in asdict(self.coverage):
            if key in coverage:
                setattr(self.coverage, key, coverage[key])
        self.metadata.update(snapshot.get("metadata") or {})

    def snapshot(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "domain": self.domain,
            "assets": [asdict(self.assets[key]) for key in sorted(self.assets)],
            "edges": [asdict(self.edges[key]) for key in sorted(self.edges)],
            "requests": [self.requests[key].public_dict() for key in sorted(self.requests)],
            "responses": [asdict(self.responses[key]) for key in sorted(self.responses)],
            "observations": [asdict(self.observations[key]) for key in sorted(self.observations)],
            "identities": [self.identities[key].public_dict() for key in sorted(self.identities)],
            "coverage": self.coverage.snapshot(),
            "metadata": dict(self.metadata),
        }

    def diff(self, previous_snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        previous = previous_snapshot or {}

        def _by_id(items: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
            return {str(item.get("id")): item for item in items if item.get("id")}

        current_snapshot = self.snapshot()
        result: Dict[str, Any] = {}
        for collection in ("assets", "edges", "requests", "observations"):
            before = _by_id(previous.get(collection, []))
            after = _by_id(current_snapshot.get(collection, []))
            new_ids = sorted(set(after) - set(before))
            removed_ids = sorted(set(before) - set(after))
            changed_ids = sorted(
                item_id
                for item_id in set(after).intersection(before)
                if _stable_json(after[item_id]) != _stable_json(before[item_id])
            )
            result[collection] = {
                "new": [after[item_id] for item_id in new_ids],
                "removed": [before[item_id] for item_id in removed_ids],
                "changed": [
                    {"before": before[item_id], "after": after[item_id]}
                    for item_id in changed_ids
                ],
            }
        return result


def infer_insertion_points(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Any = None,
    content_type: Optional[str] = None,
    source: str = "discovered",
) -> List[InsertionPoint]:
    points: List[InsertionPoint] = []
    parsed = urlsplit(url)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        points.append(
            InsertionPoint(
                location="query",
                name=name,
                value=value,
                source=source,
            )
        )

    for header_name, header_value in (headers or {}).items():
        lower = header_name.lower()
        if lower == "cookie":
            for pair in str(header_value).split(";"):
                if "=" not in pair:
                    continue
                name, value = pair.split("=", 1)
                points.append(
                    InsertionPoint(
                        location="cookie",
                        name=name.strip(),
                        value=value.strip(),
                        source=source,
                    )
                )
        elif lower == "authorization" or lower.startswith("x-"):
            points.append(
                InsertionPoint(
                    location="header",
                    name=header_name,
                    value=header_value,
                    source=source,
                )
            )

    normalized_type = (content_type or "").split(";", 1)[0].strip().lower()
    is_json_type = normalized_type == "application/json" or normalized_type.endswith("+json")
    if is_json_type or (isinstance(body, (dict, list)) and normalized_type not in {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    }):
        data = body
        if isinstance(body, (str, bytes)):
            encoded = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
            try:
                data = json.loads(encoded)
            except ValueError:
                data = None
        if data is not None:
            for name, value in _flatten_json(data):
                if name:
                    points.append(
                        InsertionPoint(
                            location="json",
                            name=name,
                            value=value,
                            value_type=type(value).__name__,
                            source=source,
                        )
                    )
    elif normalized_type == "application/x-www-form-urlencoded" and body:
        if isinstance(body, dict):
            form_items = [(str(name), "" if value is None else str(value)) for name, value in body.items()]
        else:
            encoded = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
            form_items = parse_qsl(encoded, keep_blank_values=True)
        for name, value in form_items:
            points.append(
                InsertionPoint(
                    location="body",
                    name=name,
                    value=value,
                    source=source,
                )
            )
    elif normalized_type == "multipart/form-data" and isinstance(body, dict):
        for name, value in sorted(body.items()):
            points.append(
                InsertionPoint(
                    location="body",
                    name=str(name),
                    value=value,
                    value_type=type(value).__name__,
                    source=source,
                    metadata={"multipart": True},
                )
            )
    elif normalized_type == "text/plain" and body not in (None, "", b""):
        points.append(
            InsertionPoint(
                location="body",
                name="body",
                value=body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body),
                value_type="text",
                source=source,
            )
        )

    unique: Dict[Tuple[str, str], InsertionPoint] = {}
    for point in points:
        unique[_point_logical_key(point)] = point
    return [unique[key] for key in sorted(unique)]


def encode_form(fields: Sequence[Tuple[str, Any]]) -> str:
    return urlencode([(str(name), "" if value is None else str(value)) for name, value in fields])
