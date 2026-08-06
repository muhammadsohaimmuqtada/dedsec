import json
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from dedsec.core.workspace import (
    InsertionPoint,
    RequestRecord,
    ResearchWorkspace,
    endpoint_key,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


_HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete"}


def _load_spec(path: str) -> Dict[str, Any]:
    with open(os.path.expanduser(path), "r", encoding="utf-8") as handle:
        text = handle.read()
    if path.lower().endswith(".json"):
        data = json.loads(text)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML API specifications")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("API specification must contain an object")
    return data


def _sample_scalar(schema: Dict[str, Any], name: str = "value") -> Any:
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    value_type = schema.get("type")
    value_format = schema.get("format")
    if value_type == "integer":
        return int(schema.get("minimum", 1))
    if value_type == "number":
        return float(schema.get("minimum", 1.0))
    if value_type == "boolean":
        return True
    if value_format == "email":
        return "researcher@example.invalid"
    if value_format in {"uuid", "guid"}:
        return "00000000-0000-4000-8000-000000000001"
    if value_format in {"date", "date-time"}:
        return "2026-01-01" if value_format == "date" else "2026-01-01T00:00:00Z"
    lowered = (name or "").lower()
    if lowered.endswith("id") or lowered == "id":
        return "1"
    return "sample"


def _sample_schema(schema: Any, depth: int = 0) -> Any:
    if not isinstance(schema, dict) or depth > 5:
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    schema_type = schema.get("type")
    if schema_type == "object" or isinstance(schema.get("properties"), dict):
        return {
            str(name): _sample_schema(value, depth + 1)
            for name, value in sorted((schema.get("properties") or {}).items())
        }
    if schema_type == "array":
        item = _sample_schema(schema.get("items") or {}, depth + 1)
        return [] if item is None else [item]
    return _sample_scalar(schema)


def _parameter_sample(parameter: Dict[str, Any]) -> Any:
    if "example" in parameter:
        return parameter["example"]
    schema = parameter.get("schema")
    if isinstance(schema, dict):
        return _sample_scalar(schema, str(parameter.get("name") or "value"))
    return _sample_scalar(parameter, str(parameter.get("name") or "value"))


def _merge_parameters(*groups: Any) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for group in groups:
        for parameter in group or []:
            if not isinstance(parameter, dict) or "$ref" in parameter:
                continue
            key = (str(parameter.get("in") or ""), str(parameter.get("name") or ""))
            merged[key] = parameter
    return [merged[key] for key in sorted(merged)]


class OpenAPIImporter:
    """Convert OpenAPI/Swagger definitions into non-executed request corpus entries."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def _base_url(self, spec: Dict[str, Any]) -> str:
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict) and first.get("url"):
                raw = str(first["url"])
                if raw.startswith(("http://", "https://")):
                    return raw.rstrip("/") + "/"
                return urljoin(self.target_url, raw).rstrip("/") + "/"
        if spec.get("swagger"):
            scheme = "https"
            schemes = spec.get("schemes")
            if isinstance(schemes, list) and schemes:
                scheme = str(schemes[0])
            host = spec.get("host") or urlsplit(self.target_url).netloc
            base_path = str(spec.get("basePath") or "/")
            return ("%s://%s%s" % (scheme, host, base_path.rstrip("/"))).rstrip("/") + "/"
        return self.target_url.rstrip("/") + "/"

    @staticmethod
    def _security_metadata(spec: Dict[str, Any]) -> Dict[str, Any]:
        schemes = {}
        components = spec.get("components") or {}
        raw = components.get("securitySchemes") if isinstance(components, dict) else None
        if not raw and spec.get("swagger"):
            raw = spec.get("securityDefinitions")
        for name, definition in (raw or {}).items():
            if not isinstance(definition, dict):
                continue
            schemes[str(name)] = {
                "type": definition.get("type"),
                "scheme": definition.get("scheme"),
                "in": definition.get("in"),
                "name": definition.get("name"),
                "bearer_format": definition.get("bearerFormat"),
            }
        return schemes

    def ingest(
        self,
        workspace: ResearchWorkspace,
        spec: Dict[str, Any],
        source: str = "openapi",
        identity_id: str = "identity-anonymous",
    ) -> Dict[str, Any]:
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            raise ValueError("API specification does not contain a paths object")
        base_url = self._base_url(spec)
        imported = 0
        state_changing = 0
        methods: Dict[str, int] = {}

        security_schemes = self._security_metadata(spec)
        if security_schemes:
            workspace.metadata.setdefault("api_auth_schemes", {}).update(security_schemes)

        for path_template, path_item in sorted(paths.items()):
            if not isinstance(path_item, dict):
                continue
            path_parameters = path_item.get("parameters") or []
            for method_name, operation in sorted(path_item.items()):
                if method_name.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                method = method_name.upper()
                parameters = _merge_parameters(path_parameters, operation.get("parameters"))
                rendered_path = str(path_template)
                query: List[Tuple[str, Any]] = []
                headers: Dict[str, str] = {}
                points: List[InsertionPoint] = []
                body: Any = None
                content_type: Optional[str] = None

                for parameter in parameters:
                    name = str(parameter.get("name") or "")
                    location = str(parameter.get("in") or "query").lower()
                    if not name:
                        continue
                    sample = _parameter_sample(parameter)
                    points.append(
                        InsertionPoint(
                            location=location,
                            name=name,
                            value=sample,
                            value_type=str(
                                (parameter.get("schema") or {}).get("type")
                                or parameter.get("type")
                                or "string"
                            ),
                            required=bool(parameter.get("required")),
                            source=source,
                            metadata={"path_template": path_template},
                        )
                    )
                    if location == "path":
                        rendered_path = rendered_path.replace("{%s}" % name, str(sample))
                    elif location == "query":
                        query.append((name, sample))
                    elif location == "header":
                        headers[name] = str(sample)

                request_body = operation.get("requestBody")
                if isinstance(request_body, dict):
                    content = request_body.get("content") or {}
                    preferred = None
                    for candidate_type in (
                        "application/json",
                        "application/x-www-form-urlencoded",
                        "multipart/form-data",
                    ):
                        if candidate_type in content:
                            preferred = candidate_type
                            break
                    if preferred is None and content:
                        preferred = sorted(content)[0]
                    if preferred:
                        media = content.get(preferred) or {}
                        body = media.get("example")
                        if body is None:
                            body = _sample_schema(media.get("schema") or {})
                        content_type = preferred
                elif spec.get("swagger"):
                    for parameter in parameters:
                        if parameter.get("in") == "body":
                            body = _sample_schema(parameter.get("schema") or {})
                            content_type = "application/json"
                            points.append(
                                InsertionPoint(
                                    location="body",
                                    name=str(parameter.get("name") or "body"),
                                    value=body,
                                    value_type="object",
                                    required=bool(parameter.get("required")),
                                    source=source,
                                    metadata={"path_template": path_template},
                                )
                            )

                target = urljoin(base_url, rendered_path.lstrip("/"))
                if query:
                    parsed = urlsplit(target)
                    target = urlunsplit(
                        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
                    )
                tags = ["api-spec", "not-executed"]
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    tags.append("state-changing-method")
                    state_changing += 1
                request = RequestRecord.build(
                    method,
                    target,
                    headers=headers,
                    body=body,
                    content_type=content_type,
                    identity_id=identity_id,
                    source=source,
                    insertion_points=points,
                    tags=tags,
                    metadata={
                        "path_template": path_template,
                        "operation_id": operation.get("operationId"),
                        "summary": operation.get("summary"),
                        "deprecated": bool(operation.get("deprecated")),
                        "security": operation.get("security", spec.get("security")),
                    },
                )
                workspace.add_request(request)
                template_url = urljoin(base_url, str(path_template).lstrip("/"))
                api_endpoint_id = workspace.add_asset(
                    "endpoint",
                    endpoint_key(method, template_url, path_template=str(path_template)),
                    attributes={
                        "path_template": path_template,
                        "method": method,
                        "operation_id": operation.get("operationId"),
                    },
                    source=source,
                )
                domain_id = workspace.add_asset("domain", workspace.domain, source=source)
                workspace.add_edge(
                    domain_id,
                    api_endpoint_id,
                    "exposes_api",
                    {"method": method},
                )
                imported += 1
                methods[method] = methods.get(method, 0) + 1

        return {
            "source": source,
            "base_url": base_url,
            "requests_imported": imported,
            "state_changing_requests_recorded_not_executed": state_changing,
            "methods": dict(sorted(methods.items())),
            "authentication_schemes": security_schemes,
        }

    def ingest_file(
        self,
        workspace: ResearchWorkspace,
        path: str,
        identity_id: str = "identity-anonymous",
    ) -> Dict[str, Any]:
        spec = _load_spec(path)
        result = self.ingest(
            workspace,
            spec,
            source="openapi:%s" % os.path.basename(path),
            identity_id=identity_id,
        )
        result["file"] = os.path.abspath(os.path.expanduser(path))
        result["version"] = spec.get("openapi") or spec.get("swagger")
        return result
