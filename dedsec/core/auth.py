import base64
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from dedsec.core.runtime import ScanContext
from dedsec.core.workspace import IdentityContext, stable_id

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared, guard aids embedding
    yaml = None


_SECRET_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "cookies",
}
_AUTH_KINDS = {"headers", "basic", "bearer", "api_key", "cookie", "workflow"}
_TOP_LEVEL_KEYS = {
    "label",
    "name",
    "kind",
    "type",
    "role",
    "tenant",
    "headers",
    "cookies",
    "username",
    "password",
    "token",
    "api_key_name",
    "api_key_value",
    "api_key_location",
    "workflow",
    "verification",
    "metadata",
}
_WORKFLOW_KEYS = {
    "method",
    "url",
    "headers",
    "form",
    "json",
    "timeout",
    "follow_redirects",
    "expect_status",
    "capture",
}
_VERIFICATION_KEYS = {
    "url",
    "timeout",
    "expect_status",
    "body_regex",
    "logged_out_regex",
}
_CAPTURE_KEYS = {"header", "regex", "group"}


def _load_structured_file(path: str) -> Dict[str, Any]:
    expanded = os.path.abspath(os.path.expanduser(path))
    with open(expanded, "r", encoding="utf-8") as handle:
        text = handle.read()
    if expanded.lower().endswith(".json"):
        data = json.loads(text)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML authentication profiles")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Authentication profile must contain an object at the top level")
    return data


def _reject_unknown(mapping: Any, allowed: set, label: str) -> None:
    if not isinstance(mapping, dict):
        raise ValueError("%s must be an object" % label)
    unknown = sorted(str(key) for key in mapping if str(key) not in allowed)
    if unknown:
        raise ValueError("Unknown %s key(s): %s" % (label, ", ".join(unknown)))


def _status_values(value: Any, label: str) -> List[int]:
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        try:
            code = int(item)
        except (TypeError, ValueError):
            raise ValueError("%s contains an invalid HTTP status" % label)
        if code < 100 or code > 599:
            raise ValueError("%s contains an invalid HTTP status" % label)
        result.append(code)
    return result


def _compile_regex(value: Any, label: str):
    try:
        return re.compile(str(value), re.S)
    except re.error as exc:
        raise ValueError("Invalid %s regex: %s" % (label, exc))


def _public_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    public: Dict[str, Any] = {}
    for key, value in data.items():
        lowered = str(key).lower()
        if lowered in _SECRET_KEYS or any(part in lowered for part in ("password", "secret", "token")):
            public[str(key)] = "[configured]"
        elif isinstance(value, dict):
            public[str(key)] = _public_metadata(value)
        elif isinstance(value, list):
            public[str(key)] = "[%d configured item(s)]" % len(value)
        else:
            public[str(key)] = value
    return public


def _substitute(value: Any, variables: Dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {str(k): _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(item, variables) for item in value]
    if not isinstance(value, str):
        return value
    result = value
    for key, replacement in variables.items():
        result = result.replace("${%s}" % key, str(replacement))
    return result


@dataclass
class AuthProfile:
    label: str = "authenticated"
    kind: str = "headers"
    role: Optional[str] = None
    tenant: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key_name: Optional[str] = None
    api_key_value: Optional[str] = None
    api_key_location: str = "header"
    workflow: List[Dict[str, Any]] = field(default_factory=list)
    verification: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> "AuthProfile":
        raw = _load_structured_file(path)
        _reject_unknown(raw, _TOP_LEVEL_KEYS, "authentication-profile")
        headers = raw.get("headers") or {}
        cookies = raw.get("cookies") or {}
        workflow = raw.get("workflow") or []
        verification = raw.get("verification") or {}
        metadata = raw.get("metadata") or {}
        if not isinstance(headers, dict):
            raise ValueError("Authentication headers must be an object")
        if not isinstance(cookies, dict):
            raise ValueError("Authentication cookies must be an object")
        if not isinstance(workflow, list):
            raise ValueError("Authentication workflow must be a list")
        if not isinstance(verification, dict):
            raise ValueError("Authentication verification must be an object")
        if not isinstance(metadata, dict):
            raise ValueError("Authentication metadata must be an object")
        _reject_unknown(verification, _VERIFICATION_KEYS, "verification")

        for index, step in enumerate(workflow):
            if not isinstance(step, dict):
                raise ValueError("Authentication workflow step %d must be an object" % (index + 1))
            _reject_unknown(step, _WORKFLOW_KEYS, "workflow[%d]" % index)
            method = str(step.get("method") or "GET").upper()
            if method not in {"GET", "HEAD", "POST"}:
                raise ValueError("Authentication workflow only supports GET, HEAD, and explicit POST steps")
            if method in {"GET", "HEAD"} and (step.get("form") is not None or step.get("json") is not None):
                raise ValueError("GET/HEAD authentication steps cannot declare form or json bodies")
            if step.get("form") is not None and step.get("json") is not None:
                raise ValueError("Authentication workflow step cannot contain both form and json")
            if step.get("timeout") is not None and float(step["timeout"]) <= 0:
                raise ValueError("Authentication workflow timeout must be positive")
            if step.get("expect_status") is not None:
                _status_values(step["expect_status"], "workflow[%d].expect_status" % index)
            capture = step.get("capture") or {}
            if not isinstance(capture, dict):
                raise ValueError("workflow[%d].capture must be an object" % index)
            for variable, rule in capture.items():
                if not str(variable).strip():
                    raise ValueError("Workflow capture variable names cannot be empty")
                _reject_unknown(rule, _CAPTURE_KEYS, "workflow[%d].capture.%s" % (index, variable))
                if bool(rule.get("header")) == bool(rule.get("regex")):
                    raise ValueError("Capture rules must declare exactly one of header or regex")
                if rule.get("regex"):
                    compiled = _compile_regex(rule["regex"], "workflow capture")
                    group = int(rule.get("group", 1))
                    if group < 0 or group > compiled.groups:
                        raise ValueError("Workflow capture group is outside the regex group range")

        if verification.get("timeout") is not None and float(verification["timeout"]) <= 0:
            raise ValueError("Authentication verification timeout must be positive")
        if verification.get("expect_status") is not None:
            _status_values(verification["expect_status"], "verification.expect_status")
        for key in ("body_regex", "logged_out_regex"):
            if verification.get(key):
                _compile_regex(verification[key], "verification.%s" % key)

        profile = cls(
            label=str(raw.get("label") or raw.get("name") or "authenticated"),
            kind=str(raw.get("kind") or raw.get("type") or "headers").lower(),
            role=raw.get("role"),
            tenant=raw.get("tenant"),
            headers={str(k): str(v) for k, v in headers.items()},
            cookies={str(k): str(v) for k, v in cookies.items()},
            username=raw.get("username"),
            password=raw.get("password"),
            token=raw.get("token"),
            api_key_name=raw.get("api_key_name"),
            api_key_value=raw.get("api_key_value"),
            api_key_location=str(raw.get("api_key_location") or "header").lower(),
            workflow=[dict(item) for item in workflow],
            verification=dict(verification),
            metadata=_public_metadata(metadata),
        )
        if profile.kind not in _AUTH_KINDS:
            raise ValueError("Unsupported authentication profile kind: %s" % profile.kind)
        if profile.api_key_location not in {"header"}:
            raise ValueError("Only header API keys are supported by the shared auth context")
        return profile


@dataclass
class PreparedIdentity:
    identity: IdentityContext
    headers: Dict[str, str]
    verified: bool
    verification: Dict[str, Any] = field(default_factory=dict)


class AuthManager:
    """Prepare explicit researcher-supplied authentication without auto-registration."""

    def __init__(self, context: ScanContext):
        self.context = context
        self.transport = context.get_transport()

    @staticmethod
    def _cookie_header(cookies: Dict[str, str]) -> str:
        return "; ".join("%s=%s" % (name, value) for name, value in sorted(cookies.items()))

    def _base_headers(self, profile: AuthProfile) -> Dict[str, str]:
        headers = dict(profile.headers)
        if profile.kind == "basic":
            if profile.username is None or profile.password is None:
                raise ValueError("Basic authentication requires username and password")
            raw = ("%s:%s" % (profile.username, profile.password)).encode("utf-8")
            headers["Authorization"] = "Basic %s" % base64.b64encode(raw).decode("ascii")
        elif profile.kind == "bearer":
            if not profile.token:
                raise ValueError("Bearer authentication requires token")
            headers["Authorization"] = "Bearer %s" % profile.token
        elif profile.kind == "api_key":
            if not profile.api_key_name or profile.api_key_value is None:
                raise ValueError("API-key authentication requires api_key_name and api_key_value")
            headers[profile.api_key_name] = profile.api_key_value
        cookies = dict(profile.cookies)
        if cookies:
            headers["Cookie"] = self._cookie_header(cookies)
        return headers

    def _execute_workflow(
        self,
        profile: AuthProfile,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        variables: Dict[str, str] = {}
        step_results: List[Dict[str, Any]] = []
        for index, raw_step in enumerate(profile.workflow):
            step = _substitute(raw_step, variables)
            method = str(step.get("method") or "GET").upper()
            target = urljoin(self.context.target_url, str(step.get("url") or "/"))
            decision = self.context.scope.check_url(target)
            if not decision.allowed:
                raise ValueError("Authentication workflow target outside scope: %s" % target)
            request_headers = dict(headers)
            request_headers.update(
                {str(k): str(v) for k, v in (step.get("headers") or {}).items()}
            )
            form_data = step.get("form")
            json_data = step.get("json")
            outcome = self.transport.request(
                method,
                target,
                timeout=float(step.get("timeout") or self.context.timeout),
                allow_redirects=bool(step.get("follow_redirects", True)),
                headers=request_headers,
                data=form_data,
                json_body=json_data,
                cache=False,
            )
            if outcome.response is None:
                category = outcome.failure.category if outcome.failure is not None else "request"
                raise RuntimeError("Authentication workflow transport failure: %s" % category)
            response = outcome.response
            expected = step.get("expect_status")
            if expected is not None:
                expected_codes = set(_status_values(expected, "workflow expect_status"))
                if response.status_code not in expected_codes:
                    raise RuntimeError(
                        "Authentication workflow step %d returned HTTP %d; expected %s"
                        % (index + 1, response.status_code, sorted(expected_codes))
                    )

            capture = step.get("capture") or {}
            for variable, rule in capture.items():
                if rule.get("header"):
                    header_value = response.headers.get(str(rule["header"]))
                    if header_value is not None:
                        variables[str(variable)] = str(header_value)
                elif rule.get("regex"):
                    match = re.search(str(rule["regex"]), response.text, re.S)
                    if match:
                        group = int(rule.get("group", 1))
                        variables[str(variable)] = str(match.group(group))
            step_results.append(
                {
                    "index": index + 1,
                    "method": method,
                    "url": target,
                    "status": response.status_code,
                    "attempts": outcome.attempts,
                }
            )

        session_cookies = self.transport.session_cookies()
        if session_cookies:
            headers["Cookie"] = self._cookie_header(session_cookies)
        return {"steps": step_results, "captured_variables": sorted(variables)}

    def _verify(self, profile: AuthProfile, headers: Dict[str, str]) -> Dict[str, Any]:
        verification = profile.verification or {}
        if not verification:
            return {
                "configured": False,
                "verified": False,
                "reason": "verification-not-configured",
            }
        target = urljoin(self.context.target_url, str(verification.get("url") or "/"))
        decision = self.context.scope.check_url(target)
        if not decision.allowed:
            raise ValueError("Authentication verification target outside scope")
        outcome = self.transport.request(
            "GET",
            target,
            timeout=float(verification.get("timeout") or self.context.timeout),
            allow_redirects=True,
            headers=headers,
            cache=False,
        )
        if outcome.response is None:
            return {
                "configured": True,
                "verified": False,
                "reason": outcome.failure.category if outcome.failure is not None else "transport",
            }
        response = outcome.response
        expected = verification.get("expect_status", [200])
        status_ok = response.status_code in set(_status_values(expected, "verification expect_status"))
        regex = verification.get("body_regex")
        body_ok = True if not regex else re.search(str(regex), response.text, re.S) is not None
        negative_regex = verification.get("logged_out_regex")
        logged_out = bool(negative_regex and re.search(str(negative_regex), response.text, re.S))
        return {
            "configured": True,
            "verified": bool(status_ok and body_ok and not logged_out),
            "status": response.status_code,
            "status_ok": status_ok,
            "body_signal_ok": body_ok,
            "logged_out_signal": logged_out,
        }

    def prepare(self, profile: AuthProfile) -> PreparedIdentity:
        headers = self._base_headers(profile)
        workflow_result: Dict[str, Any] = {}
        if profile.kind == "workflow" or profile.workflow:
            workflow_result = self._execute_workflow(profile, headers)
        verification = self._verify(profile, headers)
        identity_id = stable_id(
            "identity",
            {
                "label": profile.label,
                "kind": profile.kind,
                "role": profile.role,
                "tenant": profile.tenant,
            },
        )
        verified = bool(verification.get("verified"))
        identity = IdentityContext(
            id=identity_id,
            label=profile.label,
            kind=profile.kind,
            role=profile.role,
            tenant=profile.tenant,
            authenticated=verified,
            metadata={
                "verification_configured": bool(profile.verification),
                "workflow_steps": len(profile.workflow),
                "profile_metadata": profile.metadata,
            },
        )
        verification["workflow"] = workflow_result
        return PreparedIdentity(
            identity=identity,
            headers=headers,
            verified=verified,
            verification=verification,
        )
