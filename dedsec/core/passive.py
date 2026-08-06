from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional

from dedsec.core.workspace import Observation, RequestRecord, ResponseRecord


class PassivePipeline:
    """Analyze already-observed responses without sending additional requests."""

    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
    }

    def analyze(
        self,
        request: RequestRecord,
        response: ResponseRecord,
        body_text: Optional[str] = None,
    ) -> List[Observation]:
        headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
        observations: List[Observation] = []

        server = headers.get("server")
        if server:
            observations.append(
                Observation.build(
                    category="technology",
                    title="Server header observed",
                    classification="observation",
                    severity="INFO",
                    confidence="observed",
                    request_id=request.id,
                    evidence={"server": server, "status": response.status_code},
                    source="passive",
                )
            )

        present = []
        missing = []
        for header_name, label in self.SECURITY_HEADERS.items():
            if header_name in headers:
                present.append(label)
            else:
                missing.append(label)
        observations.append(
            Observation.build(
                category="headers",
                title="Security header coverage observed",
                classification="hardening-observation",
                severity="INFO",
                confidence="observed",
                request_id=request.id,
                evidence={"present": sorted(present), "missing": sorted(missing)},
                source="passive",
            )
        )

        set_cookie = headers.get("set-cookie")
        if set_cookie:
            cookie = SimpleCookie()
            try:
                cookie.load(set_cookie)
            except Exception:
                cookie = SimpleCookie()
            for name, morsel in cookie.items():
                flags: Dict[str, Any] = {
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                }
                observations.append(
                    Observation.build(
                        category="cookie",
                        title="Cookie attributes observed",
                        classification="configuration-observation",
                        severity="INFO",
                        confidence="observed",
                        request_id=request.id,
                        evidence={"cookie": name, "attributes": flags},
                        source="passive",
                    )
                )

        csp = headers.get("content-security-policy")
        if csp:
            directives: Dict[str, List[str]] = {}
            for fragment in csp.split(";"):
                parts = [item for item in fragment.strip().split() if item]
                if not parts:
                    continue
                directives[parts[0].lower()] = parts[1:]
            observations.append(
                Observation.build(
                    category="csp",
                    title="Content Security Policy observed",
                    classification="configuration-observation",
                    severity="INFO",
                    confidence="observed",
                    request_id=request.id,
                    evidence={"directives": directives},
                    source="passive",
                )
            )

        content_type = (response.content_type or "").lower()
        if "json" in content_type:
            observations.append(
                Observation.build(
                    category="content",
                    title="JSON response surface observed",
                    classification="observation",
                    severity="INFO",
                    confidence="observed",
                    request_id=request.id,
                    evidence={"content_type": response.content_type},
                    source="passive",
                )
            )
        elif "html" in content_type:
            observations.append(
                Observation.build(
                    category="content",
                    title="HTML response surface observed",
                    classification="observation",
                    severity="INFO",
                    confidence="observed",
                    request_id=request.id,
                    evidence={"content_type": response.content_type},
                    source="passive",
                )
            )

        if body_text and "password" in body_text.lower() and "<form" in body_text.lower():
            observations.append(
                Observation.build(
                    category="authentication",
                    title="Password form surface observed",
                    classification="surface-observation",
                    severity="INFO",
                    confidence="heuristic",
                    request_id=request.id,
                    evidence={"form_signal": "password-input"},
                    source="passive",
                )
            )

        unique = {item.id: item for item in observations}
        return [unique[key] for key in sorted(unique)]
