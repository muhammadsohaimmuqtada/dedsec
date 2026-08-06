import copy
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlencode, urljoin, urlsplit, urlunsplit

from dedsec.core.workspace import (
    InsertionPoint,
    RequestRecord,
    ResearchWorkspace,
    infer_insertion_points,
    merge_insertion_points,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


_HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete"}
_MAX_REF_DEPTH = 16


def _load_spec(path: str) -> Dict[str, Any]:
    expanded = os.path.abspath(os.path.expanduser(path))
    with open(expanded, "r", encoding="utf-8") as handle:
        text = handle.read()
    if expanded.lower().endswith(".json"):
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
    if value_type == "file":
        return "[file-placeholder]"
    return "sample"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_json_media_type(value: Optional[str]) -> bool:
    media = str(value or "").split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


class OpenAPIImporter:
    """Convert OpenAPI/Swagger definitions into a non-executed request corpus.

    Local JSON-Pointer references are resolved with bounded recursion. Remote
    and file references are never fetched automatically; unresolved references
    remain explicit coverage metadata. State-changing operations are modeled,
    tagged, and never executed by the importer.
    """

    def __init__(
        self,
        target_url: str,
        scope=None,
        default_headers: Optional[Dict[str, str]] = None,
    ):
        self.target_url = target_url
        self.scope = scope
        self.default_headers = {str(k): str(v) for k, v in (default_headers or {}).items()}
        self._spec: Dict[str, Any] = {}
        self._unresolved_refs: List[str] = []

    def _note_unresolved(self, value: str) -> None:
        text = str(value or "")
        if text and text not in self._unresolved_refs:
            self._unresolved_refs.append(text)

    def _pointer(self, ref: str) -> Optional[Any]:
        if not ref.startswith("#/"):
            self._note_unresolved(ref)
            return None
        current: Any = self._spec
        try:
            for raw_part in ref[2:].split("/"):
                part = unquote(raw_part).replace("~1", "/").replace("~0", "~")
                if isinstance(current, dict):
                    current = current[part]
                elif isinstance(current, list):
                    current = current[int(part)]
                else:
                    raise KeyError(part)
            return current
        except (KeyError, IndexError, TypeError, ValueError):
            self._note_unresolved(ref)
            return None

    def _resolve(self, value: Any, depth: int = 0, stack: Tuple[str, ...] = ()) -> Any:
        if depth > _MAX_REF_DEPTH:
            self._note_unresolved("[reference-depth-limit]")
            return {}
        if isinstance(value, list):
            return [self._resolve(item, depth + 1, stack) for item in value]
        if not isinstance(value, dict):
            return value

        ref = value.get("$ref")
        if ref is not None:
            ref_text = str(ref)
            if ref_text in stack:
                self._note_unresolved(ref_text + " [cycle]")
                return {
                    str(key): self._resolve(item, depth + 1, stack)
                    for key, item in value.items()
                    if key != "$ref"
                }
            target = self._pointer(ref_text)
            siblings = {str(key): item for key, item in value.items() if key != "$ref"}
            if target is None or not isinstance(target, dict):
                if target is not None:
                    self._note_unresolved(ref_text + " [non-object]")
                return {
                    key: self._resolve(item, depth + 1, stack)
                    for key, item in siblings.items()
                }
            merged = copy.deepcopy(target)
            merged.update(siblings)
            return self._resolve(merged, depth + 1, stack + (ref_text,))

        return {
            str(key): self._resolve(item, depth + 1, stack)
            for key, item in value.items()
        }

    def _sample_schema(self, schema: Any, depth: int = 0) -> Any:
        if depth > 6:
            return None
        resolved = self._resolve(schema)
        if not isinstance(resolved, dict):
            return None
        if "example" in resolved:
            return resolved["example"]
        if "default" in resolved:
            return resolved["default"]
        if "const" in resolved:
            return resolved["const"]
        schema_type = resolved.get("type")
        if schema_type == "object" or isinstance(resolved.get("properties"), dict):
            return {
                str(name): self._sample_schema(item, depth + 1)
                for name, item in sorted((resolved.get("properties") or {}).items())
            }
        if schema_type == "array":
            item = self._sample_schema(resolved.get("items") or {}, depth + 1)
            return [] if item is None else [item]
        for composition in ("allOf", "oneOf", "anyOf"):
            options = resolved.get(composition)
            if not isinstance(options, list) or not options:
                continue
            if composition == "allOf":
                merged: Dict[str, Any] = {}
                for option in options:
                    sampled = self._sample_schema(option, depth + 1)
                    if isinstance(sampled, dict):
                        merged.update(sampled)
                if merged:
                    return merged
            return self._sample_schema(options[0], depth + 1)
        return _sample_scalar(resolved)

    def _parameter_sample(self, parameter: Dict[str, Any]) -> Any:
        resolved = self._resolve(parameter)
        if not isinstance(resolved, dict):
            return "sample"
        if "example" in resolved:
            return resolved["example"]
        schema = resolved.get("schema")
        if isinstance(schema, dict):
            sampled = self._sample_schema(schema)
            if sampled is not None:
                return sampled
            return _sample_scalar(self._resolve(schema), str(resolved.get("name") or "value"))
        return _sample_scalar(resolved, str(resolved.get("name") or "value"))

    def _merge_parameters(self, *groups: Any) -> List[Dict[str, Any]]:
        merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for group in groups:
            for raw in self._resolve(group or []) or []:
                resolved = self._resolve(raw)
                if not isinstance(resolved, dict):
                    continue
                key = (str(resolved.get("in") or ""), str(resolved.get("name") or ""))
                if key[1]:
                    merged[key] = resolved
        return [merged[key] for key in sorted(merged)]

    def _base_url(self, spec: Dict[str, Any]) -> str:
        servers = self._resolve(spec.get("servers"))
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict) and first.get("url"):
                raw = str(first["url"])
                if "{" in raw or "}" in raw:
                    self._note_unresolved("server-variable:%s" % raw)
                elif raw.startswith(("http://", "https://")):
                    return raw.rstrip("/") + "/"
                else:
                    return urljoin(self.target_url, raw).rstrip("/") + "/"
        if spec.get("swagger"):
            schemes = _as_list(spec.get("schemes") or [urlsplit(self.target_url).scheme or "https"])
            scheme = str(schemes[0])
            host = str(spec.get("host") or urlsplit(self.target_url).netloc)
            base_path = str(spec.get("basePath") or "/")
            return "%s://%s%s" % (scheme, host, base_path.rstrip("/"))
        return self.target_url.rstrip("/") + "/"

    def _security_metadata(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        components = self._resolve(spec.get("components") or {})
        raw = components.get("securitySchemes") if isinstance(components, dict) else None
        if not raw and spec.get("swagger"):
            raw = spec.get("securityDefinitions")
        schemes: Dict[str, Any] = {}
        for name, definition in (self._resolve(raw or {}) or {}).items():
            if isinstance(definition, dict):
                schemes[str(name)] = {
                    "type": definition.get("type"),
                    "scheme": definition.get("scheme"),
                    "in": definition.get("in"),
                    "name": definition.get("name"),
                    "bearer_format": definition.get("bearerFormat"),
                }
        return schemes

    def _scope_allowed(self, url: str) -> bool:
        if self.scope is not None:
            return bool(self.scope.check_url(url).allowed)
        target = urlsplit(self.target_url)
        candidate = urlsplit(url)
        return (
            candidate.scheme in {"http", "https"}
            and (candidate.hostname or "").lower() == (target.hostname or "").lower()
        )

    @staticmethod
    def _set_sample_header(headers: Dict[str, str], name: str, value: Any) -> None:
        lowered = str(name).lower()
        if any(str(existing).lower() == lowered for existing in headers):
            return
        headers[str(name)] = str(value)

    @staticmethod
    def _swagger_content_type(spec: Dict[str, Any], operation: Dict[str, Any], form_data: bool) -> str:
        consumes = [str(item).lower() for item in _as_list(operation.get("consumes") or spec.get("consumes"))]
        if form_data:
            if "multipart/form-data" in consumes:
                return "multipart/form-data"
            return "application/x-www-form-urlencoded"
        if consumes:
            return consumes[0]
        return "application/json"

    def ingest(
        self,
        workspace: ResearchWorkspace,
        spec: Dict[str, Any],
        source: str = "openapi",
        identity_id: str = "identity-anonymous",
    ) -> Dict[str, Any]:
        self._spec = spec
        self._unresolved_refs = []
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            raise ValueError("API specification does not contain a paths object")

        base_url = self._base_url(spec)
        security_schemes = self._security_metadata(spec)
        if security_schemes:
            workspace.metadata.setdefault("api_auth_schemes", {}).update(security_schemes)

        imported = 0
        state_changing = 0
        out_of_scope = 0
        methods: Dict[str, int] = {}

        for path_template, raw_path_item in sorted(paths.items()):
            path_item = self._resolve(raw_path_item)
            if not isinstance(path_item, dict):
                continue
            path_parameters = path_item.get("parameters") or []
            for method_name, raw_operation in sorted(path_item.items()):
                if method_name.lower() not in _HTTP_METHODS:
                    continue
                operation = self._resolve(raw_operation)
                if not isinstance(operation, dict):
                    continue

                method = method_name.upper()
                parameters = self._merge_parameters(path_parameters, operation.get("parameters"))
                rendered_path = str(path_template)
                query: List[Tuple[str, Any]] = []
                headers = dict(self.default_headers)
                explicit_points: List[InsertionPoint] = []
                body: Any = None
                content_type: Optional[str] = None
                swagger_form: Dict[str, Any] = {}
                swagger_body_parameter: Optional[Dict[str, Any]] = None

                for parameter in parameters:
                    name = str(parameter.get("name") or "")
                    location = str(parameter.get("in") or "query").lower()
                    if not name:
                        continue
                    sample = self._parameter_sample(parameter)
                    schema = self._resolve(parameter.get("schema") or {})
                    value_type = str(
                        schema.get("type")
                        if isinstance(schema, dict) and schema.get("type")
                        else parameter.get("type") or "string"
                    )

                    if location == "body":
                        swagger_body_parameter = parameter
                        continue
                    point_location = "body" if location == "formdata" else location
                    explicit_points.append(
                        InsertionPoint(
                            location=point_location,
                            name=name,
                            value=sample,
                            value_type=value_type,
                            required=bool(parameter.get("required")),
                            source=source,
                            metadata={
                                "path_template": path_template,
                                "parameter_in": location,
                            },
                        )
                    )
                    if location == "path":
                        rendered_path = rendered_path.replace("{%s}" % name, str(sample))
                    elif location == "query":
                        query.append((name, sample))
                    elif location == "header":
                        self._set_sample_header(headers, name, sample)
                    elif location == "formdata":
                        swagger_form[name] = sample

                request_body = self._resolve(operation.get("requestBody"))
                if isinstance(request_body, dict):
                    content = self._resolve(request_body.get("content") or {})
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
                        media = self._resolve(content.get(preferred) or {})
                        body = media.get("example") if isinstance(media, dict) else None
                        if body is None and isinstance(media, dict):
                            body = self._sample_schema(media.get("schema") or {})
                        content_type = preferred
                        if not _is_json_media_type(preferred) and preferred not in {
                            "application/x-www-form-urlencoded",
                            "multipart/form-data",
                        }:
                            explicit_points.append(
                                InsertionPoint(
                                    location="body",
                                    name="$body",
                                    value=body,
                                    value_type="opaque",
                                    source=source,
                                    metadata={"media_type": preferred},
                                )
                            )
                elif spec.get("swagger"):
                    if swagger_form:
                        body = swagger_form
                        content_type = self._swagger_content_type(spec, operation, form_data=True)
                    elif swagger_body_parameter is not None:
                        body = self._sample_schema(swagger_body_parameter.get("schema") or {})
                        content_type = self._swagger_content_type(spec, operation, form_data=False)
                        if not _is_json_media_type(content_type):
                            explicit_points.append(
                                InsertionPoint(
                                    location="body",
                                    name="$body",
                                    value=body,
                                    value_type="opaque",
                                    source=source,
                                    metadata={"media_type": content_type},
                                )
                            )

                target = urljoin(base_url, rendered_path.lstrip("/"))
                if query:
                    parsed = urlsplit(target)
                    target = urlunsplit(
                        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
                    )

                inferred_points = infer_insertion_points(
                    method,
                    target,
                    headers=headers,
                    body=body,
                    content_type=content_type,
                    source=source,
                )
                points = merge_insertion_points(inferred_points, explicit_points)

                tags = ["api-spec", "not-executed"]
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    tags.append("state-changing-method")
                    state_changing += 1
                scope_allowed = self._scope_allowed(target)
                if not scope_allowed:
                    tags.append("out-of-scope-spec")
                    out_of_scope += 1

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
                        "scope_allowed": scope_allowed,
                        "identity_headers_attached": bool(self.default_headers),
                    },
                )
                workspace.add_request(request)

                endpoint_id = workspace.add_asset(
                    "endpoint",
                    urljoin(base_url, str(path_template).lstrip("/")),
                    attributes={
                        "path_template": path_template,
                        "method": method,
                        "operation_id": operation.get("operationId"),
                        "scope_allowed": scope_allowed,
                    },
                    source=source,
                )
                if scope_allowed:
                    domain_id = workspace.add_asset("domain", workspace.domain, source=source)
                    workspace.add_edge(domain_id, endpoint_id, "exposes_api", {"method": method})

                imported += 1
                methods[method] = methods.get(method, 0) + 1

        unresolved = sorted(self._unresolved_refs)
        return {
            "source": source,
            "base_url": base_url,
            "requests_imported": imported,
            "state_changing_requests_recorded_not_executed": state_changing,
            "out_of_scope_requests_recorded_not_executed": out_of_scope,
            "methods": dict(sorted(methods.items())),
            "authentication_schemes": security_schemes,
            "unresolved_references": unresolved,
            "unresolved_reference_count": len(unresolved),
            "remote_references_fetched": 0,
            "identity_headers_attached": bool(self.default_headers),
        }

    def ingest_file(
        self,
        workspace: ResearchWorkspace,
        path: str,
        identity_id: str = "identity-anonymous",
    ) -> Dict[str, Any]:
        expanded = os.path.abspath(os.path.expanduser(path))
        spec = _load_spec(expanded)
        result = self.ingest(
            workspace,
            spec,
            source="openapi:%s" % os.path.basename(expanded),
            identity_id=identity_id,
        )
        result["file"] = expanded
        result["version"] = spec.get("openapi") or spec.get("swagger")
        return result
