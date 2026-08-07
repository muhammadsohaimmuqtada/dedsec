import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dedsec.core.workspace import InsertionPoint, Observation, RequestRecord, ResearchWorkspace


@dataclass
class AuditConfig:
    max_requests: int = 100
    max_insertion_points: int = 250
    reflection_probe: bool = True
    identity_id: Optional[str] = None


class AuditEngine:
    """Bounded insertion-point coverage engine.

    The built-in active probe is intentionally narrow: it mutates one query
    parameter at a time with a harmless marker and records reflection as an
    observation only. It does not attempt script execution, SQL syntax,
    command syntax, traversal payloads, state-changing methods, or auth bypass.
    """

    SAFE_METHODS = {"GET", "HEAD"}

    def __init__(self, context, workspace: ResearchWorkspace, config: Optional[AuditConfig] = None):
        self.context = context
        self.workspace = workspace
        self.config = config or AuditConfig()
        self.transport = context.get_transport()

    @staticmethod
    def _marker(request_id: str, point: InsertionPoint) -> str:
        seed = "%s:%s:%s" % (request_id, point.location, point.name)
        return "dedsec-%s" % hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _replace_query_value(url: str, name: str, marker: str) -> Optional[str]:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        changed = False
        rendered = []
        for key, value in pairs:
            if key == name and not changed:
                rendered.append((key, marker))
                changed = True
            else:
                rendered.append((key, value))
        if not changed:
            return None
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(rendered), "")
        )

    def _eligible(self, request: RequestRecord, point: InsertionPoint) -> Optional[str]:
        if request.method not in self.SAFE_METHODS:
            return "non-idempotent-method"
        if point.location != "query":
            return "unsupported-active-location"
        if self.config.identity_id and request.identity_id != self.config.identity_id:
            return "identity-filter"
        return None

    def _partition_points(
        self,
        request: RequestRecord,
    ) -> Tuple[List[InsertionPoint], List[Tuple[InsertionPoint, str]]]:
        eligible: List[InsertionPoint] = []
        not_applicable: List[Tuple[InsertionPoint, str]] = []
        for point in request.insertion_points:
            reason = self._eligible(request, point)
            if reason:
                not_applicable.append((point, reason))
            else:
                eligible.append(point)
        return eligible, not_applicable

    def _probe_reflection(
        self,
        request: RequestRecord,
        point: InsertionPoint,
    ) -> Dict[str, Any]:
        marker = self._marker(request.id, point)
        mutated = self._replace_query_value(request.url, point.name, marker)
        if not mutated:
            return {"status": "skipped", "reason": "query-parameter-not-found"}

        baseline = self.transport.request(
            request.method,
            request.url,
            timeout=self.context.timeout,
            allow_redirects=True,
            headers=request.headers,
            cache=True,
        )
        if baseline.response is None:
            return {
                "status": "inconclusive",
                "reason": baseline.failure.category if baseline.failure else "baseline-transport",
            }
        if marker in baseline.response.text:
            return {"status": "skipped", "reason": "marker-collision"}

        probe = self.transport.request(
            request.method,
            mutated,
            timeout=self.context.timeout,
            allow_redirects=True,
            headers=request.headers,
            cache=False,
        )
        if probe.response is None:
            return {
                "status": "inconclusive",
                "reason": probe.failure.category if probe.failure else "probe-transport",
            }

        reflected = marker in probe.response.text
        evidence = {
            "location": point.location,
            "name": point.name,
            "baseline_status": baseline.response.status_code,
            "probe_status": probe.response.status_code,
            "marker_reflected": reflected,
            "control_marker_absent_in_baseline": True,
        }
        if reflected:
            observation = Observation.build(
                category="input-surface",
                title="Query input reflection observed",
                classification="surface-observation",
                severity="INFO",
                confidence="controlled-differential",
                request_id=request.id,
                evidence=evidence,
                source="audit:reflection",
            )
            self.workspace.add_observation(observation)
            return {
                "status": "observed",
                "observation_id": observation.id,
                "evidence": evidence,
            }
        return {"status": "no-observation", "evidence": evidence}

    @staticmethod
    def _bump(mapping: Dict[str, int], key: str, amount: int = 1) -> None:
        mapping[key] = mapping.get(key, 0) + max(0, int(amount))

    def run(self, requests: Optional[Iterable[RequestRecord]] = None) -> Dict[str, Any]:
        corpus = list(requests) if requests is not None else list(self.workspace.requests.values())
        corpus.sort(key=lambda item: (item.method, item.url, item.id))
        coverage = self.workspace.coverage
        request_limit = max(1, int(self.config.max_requests))
        point_limit = max(1, int(self.config.max_insertion_points))
        request_count = 0
        point_count = 0
        requests_not_applicable = 0
        points_not_applicable = 0
        outcomes: Dict[str, int] = {}
        details: List[Dict[str, Any]] = []

        for request in corpus:
            if not request.insertion_points:
                coverage.requests_not_applicable += 1
                requests_not_applicable += 1
                self._bump(coverage.not_applicable_reasons, "no-insertion-points")
                continue

            eligible_points, ineligible_points = self._partition_points(request)
            if ineligible_points:
                coverage.insertion_points_not_applicable += len(ineligible_points)
                points_not_applicable += len(ineligible_points)
                for _, reason in ineligible_points:
                    self._bump(coverage.not_applicable_reasons, reason)

            if not eligible_points:
                coverage.requests_not_applicable += 1
                requests_not_applicable += 1
                continue

            coverage.requests_audit_eligible += 1
            coverage.insertion_points_audit_eligible += len(eligible_points)

            if request_count >= request_limit:
                coverage.requests_skipped += 1
                coverage.insertion_points_skipped += len(eligible_points)
                self._bump(coverage.skipped_reasons, "audit-request-limit")
                self._bump(outcomes, "skipped", len(eligible_points))
                for point in eligible_points:
                    details.append(
                        {
                            "request_id": request.id,
                            "insertion_point_id": point.id,
                            "location": point.location,
                            "name": point.name,
                            "status": "skipped",
                            "reason": "audit-request-limit",
                            "observation_id": None,
                        }
                    )
                continue

            request_count += 1
            audited_for_request = 0
            skipped_for_request = 0

            for index, point in enumerate(eligible_points):
                if point_count >= point_limit:
                    remaining = len(eligible_points) - index
                    coverage.insertion_points_skipped += remaining
                    self._bump(
                        coverage.skipped_reasons,
                        "audit-insertion-point-limit",
                        remaining,
                    )
                    self._bump(outcomes, "skipped", remaining)
                    skipped_for_request += remaining
                    for remaining_point in eligible_points[index:]:
                        details.append(
                            {
                                "request_id": request.id,
                                "insertion_point_id": remaining_point.id,
                                "location": remaining_point.location,
                                "name": remaining_point.name,
                                "status": "skipped",
                                "reason": "audit-insertion-point-limit",
                                "observation_id": None,
                            }
                        )
                    break

                point_count += 1
                if not self.config.reflection_probe:
                    coverage.insertion_points_skipped += 1
                    self._bump(coverage.skipped_reasons, "audit-disabled")
                    skipped_for_request += 1
                    self._bump(outcomes, "skipped")
                    details.append(
                        {
                            "request_id": request.id,
                            "insertion_point_id": point.id,
                            "location": point.location,
                            "name": point.name,
                            "status": "skipped",
                            "reason": "audit-disabled",
                            "observation_id": None,
                        }
                    )
                    continue

                result = self._probe_reflection(request, point)
                status = str(result.get("status") or "unknown")
                self._bump(outcomes, status)
                details.append(
                    {
                        "request_id": request.id,
                        "insertion_point_id": point.id,
                        "location": point.location,
                        "name": point.name,
                        "status": status,
                        "reason": result.get("reason"),
                        "observation_id": result.get("observation_id"),
                    }
                )
                if status in {"observed", "no-observation"}:
                    coverage.insertion_points_audited += 1
                    audited_for_request += 1
                else:
                    coverage.insertion_points_skipped += 1
                    reason_key = str(result.get("reason") or status)
                    self._bump(coverage.skipped_reasons, reason_key)
                    skipped_for_request += 1

            if audited_for_request:
                coverage.requests_audited += 1
            elif skipped_for_request:
                coverage.requests_skipped += 1

        return {
            "requests_considered": request_count,
            "requests_audit_eligible": coverage.requests_audit_eligible,
            "requests_not_applicable": requests_not_applicable,
            "insertion_points_considered": point_count,
            "insertion_points_audit_eligible": coverage.insertion_points_audit_eligible,
            "insertion_points_not_applicable": points_not_applicable,
            "outcomes": dict(sorted(outcomes.items())),
            "details": details,
            "limits": {
                "max_requests": self.config.max_requests,
                "max_insertion_points": self.config.max_insertion_points,
            },
        }
