import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from dedsec.core.scan_plan import IMPACT_LEVELS, impact_allowed
from dedsec.core.workspace import Observation, RequestRecord, ResearchWorkspace

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_ALLOWED_CLASSIFICATIONS = {
    "observation",
    "surface-observation",
    "configuration-observation",
    "hardening-observation",
    "candidate",
}
_ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_PASSIVE_MATCHERS = {"status", "header"}
_PASSIVE_EXTRACTORS = {"header"}


def _load_document(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if path.lower().endswith(".json"):
        data = json.loads(text)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML templates")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Template must contain an object")
    return data


def _canonical_digest(raw: Dict[str, Any]) -> str:
    payload = dict(raw)
    payload.pop("sha256", None)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _matcher_type(item: Dict[str, Any]) -> str:
    return str(item.get("type") or "word").lower()


@dataclass
class TemplateDefinition:
    template_id: str
    name: str
    description: str = ""
    impact: str = "active-safe"
    mode: str = "request"
    request: Dict[str, Any] = field(default_factory=dict)
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    negative_matchers: List[Dict[str, Any]] = field(default_factory=list)
    extractors: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "INFO"
    classification: str = "candidate"
    references: List[str] = field(default_factory=list)
    source_path: Optional[str] = None
    integrity: str = "unsigned"

    @classmethod
    def from_raw(
        cls,
        raw: Dict[str, Any],
        source_path: Optional[str] = None,
    ) -> "TemplateDefinition":
        template_id = str(raw.get("id") or "").strip()
        if not re.match(r"^[A-Za-z0-9_.:-]{3,120}$", template_id):
            raise ValueError("Template id must be 3-120 safe identifier characters")

        impact = str(raw.get("impact") or "active-safe").lower()
        if impact not in IMPACT_LEVELS:
            raise ValueError("Unknown template impact class: %s" % impact)
        mode = str(raw.get("mode") or "request").lower()
        if mode not in {"request", "passive"}:
            raise ValueError("Template mode must be request or passive")

        classification = str(raw.get("classification") or "candidate").lower()
        if classification not in _ALLOWED_CLASSIFICATIONS:
            raise ValueError(
                "Template classification must be one of: %s; templates cannot self-verify findings"
                % ", ".join(sorted(_ALLOWED_CLASSIFICATIONS))
            )
        severity = str(raw.get("severity") or "INFO").upper()
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError("Unsupported template severity: %s" % severity)

        request = dict(raw.get("request") or {})
        method = str(request.get("method") or "GET").upper()
        if mode == "passive" and impact != "passive":
            raise ValueError("Passive templates must declare passive impact")
        if method not in _SAFE_METHODS and impact not in {"state-changing", "high-impact"}:
            raise ValueError("Non-idempotent template method requires state-changing impact class")

        matchers = [dict(item) for item in raw.get("matchers") or [] if isinstance(item, dict)]
        negative_matchers = [
            dict(item) for item in raw.get("negative_matchers") or [] if isinstance(item, dict)
        ]
        extractors = [dict(item) for item in raw.get("extractors") or [] if isinstance(item, dict)]
        if not matchers:
            raise ValueError("Template must define at least one matcher")
        if mode == "passive":
            unsupported_matchers = sorted(
                {
                    _matcher_type(item)
                    for item in matchers + negative_matchers
                    if _matcher_type(item) not in _PASSIVE_MATCHERS
                }
            )
            unsupported_extractors = sorted(
                {
                    str(item.get("type") or "regex").lower()
                    for item in extractors
                    if str(item.get("type") or "regex").lower() not in _PASSIVE_EXTRACTORS
                }
            )
            if unsupported_matchers:
                raise ValueError(
                    "Passive templates cannot use body matchers because response bodies are not retained: %s"
                    % ", ".join(unsupported_matchers)
                )
            if unsupported_extractors:
                raise ValueError(
                    "Passive templates only support header extractors: %s"
                    % ", ".join(unsupported_extractors)
                )

        declared_digest = raw.get("sha256")
        integrity = "unsigned"
        if declared_digest:
            calculated = _canonical_digest(raw)
            if str(declared_digest).lower() != calculated:
                raise ValueError("Template sha256 integrity mismatch")
            integrity = "sha256-integrity-verified"

        return cls(
            template_id=template_id,
            name=str(raw.get("name") or template_id),
            description=str(raw.get("description") or ""),
            impact=impact,
            mode=mode,
            request=request,
            matchers=matchers,
            negative_matchers=negative_matchers,
            extractors=extractors,
            severity=severity,
            classification=classification,
            references=[str(item) for item in raw.get("references") or []],
            source_path=source_path,
            integrity=integrity,
        )

    @classmethod
    def load(cls, path: str) -> "TemplateDefinition":
        expanded = os.path.abspath(os.path.expanduser(path))
        return cls.from_raw(_load_document(expanded), source_path=expanded)


class TemplateRepository:
    def __init__(self, directories: Sequence[str], max_templates: int = 500):
        self.directories = [os.path.abspath(os.path.expanduser(item)) for item in directories]
        self.max_templates = max(1, int(max_templates))

    def load(self) -> List[TemplateDefinition]:
        templates: Dict[str, TemplateDefinition] = {}
        for directory in self.directories:
            if not os.path.isdir(directory):
                continue
            for root, _, files in os.walk(directory):
                for name in sorted(files):
                    if not name.lower().endswith((".yaml", ".yml", ".json")):
                        continue
                    definition = TemplateDefinition.load(os.path.join(root, name))
                    if definition.template_id in templates:
                        raise ValueError("Duplicate template id: %s" % definition.template_id)
                    templates[definition.template_id] = definition
                    if len(templates) >= self.max_templates:
                        return [templates[key] for key in sorted(templates)]
        return [templates[key] for key in sorted(templates)]


class TemplateRunner:
    """Deterministic declarative check runner with impact enforcement.

    A SHA-256 field verifies file integrity only; it is not an author identity or
    cryptographic signature. Template matches become observations/candidates and
    are never promoted to verified vulnerabilities solely because a template matched.
    """

    def __init__(
        self,
        context,
        workspace: ResearchWorkspace,
        maximum_impact: str = "active-safe",
    ):
        self.context = context
        self.workspace = workspace
        requested_ceiling = str(maximum_impact or "active-safe").lower()
        scan_ceiling = str(
            (getattr(context, "metadata", {}) or {}).get("maximum_impact")
            or requested_ceiling
        ).lower()
        if requested_ceiling not in IMPACT_LEVELS:
            raise ValueError("Unknown template impact ceiling: %s" % requested_ceiling)
        if scan_ceiling not in IMPACT_LEVELS:
            raise ValueError("Unknown scan impact ceiling: %s" % scan_ceiling)
        self.maximum_impact = (
            requested_ceiling
            if impact_allowed(requested_ceiling, scan_ceiling)
            else scan_ceiling
        )
        self.transport = context.get_transport()

    @staticmethod
    def _matcher(
        matcher: Dict[str, Any],
        status: int,
        headers: Dict[str, str],
        text: str,
    ) -> bool:
        matcher_type = _matcher_type(matcher)
        negate = bool(matcher.get("negate", False))
        result = False
        if matcher_type == "status":
            values = matcher.get("values", matcher.get("value", []))
            values = values if isinstance(values, list) else [values]
            result = status in {int(item) for item in values}
        elif matcher_type == "header":
            name = str(matcher.get("name") or "").lower()
            value = str(matcher.get("value") or "")
            actual = {str(k).lower(): str(v) for k, v in headers.items()}.get(name, "")
            result = value.lower() in actual.lower() if value else bool(actual)
        elif matcher_type == "regex":
            pattern = str(matcher.get("pattern") or "")
            result = bool(pattern) and re.search(pattern, text, re.S | re.I) is not None
        elif matcher_type == "word":
            value = str(matcher.get("value") or "")
            result = bool(value) and value.lower() in text.lower()
        else:
            raise ValueError("Unsupported matcher type: %s" % matcher_type)
        return not result if negate else result

    @classmethod
    def _match_group(
        cls,
        matchers: Sequence[Dict[str, Any]],
        status: int,
        headers: Dict[str, str],
        text: str,
    ) -> bool:
        if not matchers:
            return False
        required = [
            item
            for item in matchers
            if str(item.get("condition") or "and").lower() != "or"
        ]
        optional = [
            item
            for item in matchers
            if str(item.get("condition") or "and").lower() == "or"
        ]
        if required and not all(cls._matcher(item, status, headers, text) for item in required):
            return False
        if optional and not any(cls._matcher(item, status, headers, text) for item in optional):
            return False
        return True

    @staticmethod
    def _extract(
        extractors: Sequence[Dict[str, Any]],
        headers: Dict[str, str],
        text: str,
    ) -> Dict[str, Any]:
        extracted: Dict[str, Any] = {}
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        for item in extractors:
            name = str(item.get("name") or "value")
            extractor_type = str(item.get("type") or "regex").lower()
            if extractor_type == "header":
                value = lower_headers.get(str(item.get("header") or "").lower())
                if value is not None:
                    extracted[name] = value
            elif extractor_type == "regex" and text:
                match = re.search(str(item.get("pattern") or ""), text, re.S | re.I)
                if match:
                    group = int(item.get("group", 1 if match.lastindex else 0))
                    extracted[name] = match.group(group)
            elif extractor_type not in {"header", "regex"}:
                raise ValueError("Unsupported extractor type: %s" % extractor_type)
        return extracted

    def _request_target(self, definition: TemplateDefinition) -> RequestRecord:
        request = definition.request
        method = str(request.get("method") or "GET").upper()
        path = str(request.get("path") or "/")
        target = urljoin(self.context.target_url, path)
        query = request.get("query") or {}
        if query:
            parsed = urlsplit(target)
            target = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(sorted((str(k), str(v)) for k, v in query.items())),
                    "",
                )
            )
        return RequestRecord.build(
            method,
            target,
            headers={str(k): str(v) for k, v in (request.get("headers") or {}).items()},
            identity_id=getattr(self.context, "identity_id", "identity-anonymous"),
            source="template:%s" % definition.template_id,
            tags=["template", definition.impact],
            metadata={"template_id": definition.template_id, "integrity": definition.integrity},
        )

    def _observation(
        self,
        definition: TemplateDefinition,
        request_id: Optional[str],
        evidence: Dict[str, Any],
        confidence: str,
    ) -> Observation:
        return Observation.build(
            category="template",
            title=definition.name,
            classification=definition.classification,
            severity=definition.severity,
            confidence=confidence,
            request_id=request_id,
            evidence=evidence,
            source="template:%s" % definition.template_id,
        )

    def _run_passive(self, definition: TemplateDefinition) -> Dict[str, Any]:
        matches = []
        for response in sorted(self.workspace.responses.values(), key=lambda item: item.id):
            text = ""
            negative_hit = (
                self._match_group(
                    definition.negative_matchers,
                    response.status_code,
                    response.headers,
                    text,
                )
                if definition.negative_matchers
                else False
            )
            positive = self._match_group(
                definition.matchers,
                response.status_code,
                response.headers,
                text,
            )
            if positive and not negative_hit:
                evidence = {
                    "status": response.status_code,
                    "response_id": response.id,
                    "extractors": self._extract(definition.extractors, response.headers, text),
                    "template_id": definition.template_id,
                    "integrity": definition.integrity,
                    "references": definition.references,
                    "body_retained": False,
                }
                observation = self._observation(
                    definition,
                    response.request_id,
                    evidence,
                    "passive-template-match",
                )
                self.workspace.add_observation(observation)
                matches.append(observation.id)
        return {
            "id": definition.template_id,
            "status": "matched" if matches else "no-match",
            "observation_ids": matches,
            "mode": "passive",
            "network_requests": 0,
        }

    def _run_request(self, definition: TemplateDefinition) -> Dict[str, Any]:
        request = self._request_target(definition)
        if not self.context.scope.check_url(request.url).allowed:
            return {"id": definition.template_id, "status": "skipped", "reason": "scope"}
        self.workspace.add_request(request)

        if request.method not in _SAFE_METHODS:
            return {
                "id": definition.template_id,
                "status": "skipped",
                "reason": "state-changing-template-execution-disabled",
            }

        outcome = self.transport.request(
            request.method,
            request.url,
            timeout=self.context.timeout,
            allow_redirects=False,
            headers=request.headers,
            cache=True,
        )
        if outcome.response is None:
            self.workspace.coverage.skip_request(
                "template-transport:%s"
                % (outcome.failure.category if outcome.failure is not None else "unknown"),
                len(request.insertion_points),
            )
            return {
                "id": definition.template_id,
                "status": "inconclusive",
                "reason": outcome.failure.category if outcome.failure is not None else "transport",
            }

        response = outcome.response
        text = response.text[: 2 * 1024 * 1024]
        negative_hit = (
            self._match_group(
                definition.negative_matchers,
                response.status_code,
                dict(response.headers),
                text,
            )
            if definition.negative_matchers
            else False
        )
        positive = self._match_group(
            definition.matchers,
            response.status_code,
            dict(response.headers),
            text,
        )
        self.workspace.coverage.audit_request(len(request.insertion_points))
        if positive and not negative_hit:
            evidence = {
                "status": response.status_code,
                "extractors": self._extract(definition.extractors, dict(response.headers), text),
                "template_id": definition.template_id,
                "integrity": definition.integrity,
                "references": definition.references,
            }
            observation = self._observation(
                definition,
                request.id,
                evidence,
                "template-match",
            )
            self.workspace.add_observation(observation)
            return {
                "id": definition.template_id,
                "status": "matched",
                "observation_id": observation.id,
                "mode": "request",
            }
        return {"id": definition.template_id, "status": "no-match", "mode": "request"}

    def run_template(self, definition: TemplateDefinition) -> Dict[str, Any]:
        if not impact_allowed(definition.impact, self.maximum_impact):
            return {"id": definition.template_id, "status": "skipped", "reason": "impact-policy"}
        if definition.mode == "passive":
            return self._run_passive(definition)
        return self._run_request(definition)

    def run(self, definitions: Iterable[TemplateDefinition]) -> Dict[str, Any]:
        results = [self.run_template(item) for item in definitions]
        counts: Dict[str, int] = {}
        for item in results:
            status = str(item.get("status") or "unknown")
            counts[status] = counts.get(status, 0) + 1
        return {"counts": dict(sorted(counts.items())), "results": results}
