import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


IMPACT_LEVELS = {
    "passive": 0,
    "normal": 1,
    "active-safe": 2,
    "state-changing": 3,
    "high-impact": 4,
}


def impact_allowed(requested: str, maximum: str) -> bool:
    if requested not in IMPACT_LEVELS:
        raise ValueError("Unknown impact class: %s" % requested)
    if maximum not in IMPACT_LEVELS:
        raise ValueError("Unknown maximum impact class: %s" % maximum)
    return IMPACT_LEVELS[requested] <= IMPACT_LEVELS[maximum]


def _load(path: str) -> Dict[str, Any]:
    expanded = os.path.abspath(os.path.expanduser(path))
    with open(expanded, "r", encoding="utf-8") as handle:
        text = handle.read()
    if expanded.lower().endswith(".json"):
        data = json.loads(text)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required to load YAML scan plans")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Scan plan must contain an object at the top level")
    return data


def _list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _reject_unknown(mapping: Any, allowed: set, label: str) -> None:
    if not isinstance(mapping, dict):
        raise ValueError("%s must be an object" % label)
    unknown = sorted(str(key) for key in mapping if str(key) not in allowed)
    if unknown:
        raise ValueError("Unknown %s key(s): %s" % (label, ", ".join(unknown)))


def _resolve_path(base_dir: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = os.path.expanduser(str(value))
    if not os.path.isabs(text):
        text = os.path.join(base_dir, text)
    return os.path.abspath(text)


def _unique_strings(values: Any) -> List[str]:
    result = []
    seen = set()
    for item in _list(values):
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


@dataclass
class ScopePlan:
    allowed_hosts: List[str] = field(default_factory=list)
    denied_hosts: List[str] = field(default_factory=list)
    allowed_ports: Optional[List[int]] = None
    include_subdomains: bool = True
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)


@dataclass
class DiscoveryPlan:
    enabled: bool = False
    crawl_depth: int = 3
    crawl_pages: int = 200
    crawl_body_bytes: int = 2 * 1024 * 1024
    javascript_candidates: bool = True
    browser: bool = False
    api_specs: List[str] = field(default_factory=list)


@dataclass
class TrafficPlan:
    timeout: int = 10
    concurrency: int = 5
    module_timeout: int = 120
    global_timeout: int = 600
    retries: int = 3
    module_retries: int = 1
    backoff: float = 0.5
    max_requests: int = 1000
    maximum_impact: str = "active-safe"


@dataclass
class ProjectPlan:
    database: Optional[str] = None
    resume: bool = False
    diff: bool = True


@dataclass
class TemplatePlan:
    directories: List[str] = field(default_factory=list)
    maximum_impact: str = "active-safe"
    max_templates: int = 500


@dataclass
class ExportPlan:
    formats: List[str] = field(default_factory=lambda: ["json"])
    directory: Optional[str] = None


@dataclass
class ScanPlan:
    target: Optional[str] = None
    modules: List[str] = field(default_factory=list)
    scope: ScopePlan = field(default_factory=ScopePlan)
    discovery: DiscoveryPlan = field(default_factory=DiscoveryPlan)
    traffic: TrafficPlan = field(default_factory=TrafficPlan)
    project: ProjectPlan = field(default_factory=ProjectPlan)
    templates: TemplatePlan = field(default_factory=TemplatePlan)
    exports: ExportPlan = field(default_factory=ExportPlan)
    auth_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[str] = None

    @classmethod
    def load(cls, path: str) -> "ScanPlan":
        expanded_path = os.path.abspath(os.path.expanduser(path))
        base_dir = os.path.dirname(expanded_path)
        raw = _load(expanded_path)
        _reject_unknown(
            raw,
            {
                "target",
                "modules",
                "scope",
                "discovery",
                "traffic",
                "project",
                "templates",
                "exports",
                "auth_file",
                "auth",
                "metadata",
            },
            "scan-plan",
        )
        scope = raw.get("scope") or {}
        discovery = raw.get("discovery") or {}
        traffic = raw.get("traffic") or {}
        project = raw.get("project") or {}
        templates = raw.get("templates") or {}
        exports = raw.get("exports") or {}
        auth = raw.get("auth") or {}

        _reject_unknown(
            scope,
            {
                "allowed_hosts",
                "denied_hosts",
                "allowed_ports",
                "include_subdomains",
                "include_paths",
                "exclude_paths",
            },
            "scope",
        )
        _reject_unknown(
            discovery,
            {
                "enabled",
                "crawl_depth",
                "crawl_pages",
                "crawl_body_bytes",
                "javascript_candidates",
                "browser",
                "api_specs",
            },
            "discovery",
        )
        _reject_unknown(
            traffic,
            {
                "timeout",
                "concurrency",
                "module_timeout",
                "global_timeout",
                "retries",
                "module_retries",
                "backoff",
                "max_requests",
                "maximum_impact",
            },
            "traffic",
        )
        _reject_unknown(project, {"database", "resume", "diff"}, "project")
        _reject_unknown(
            templates,
            {"directories", "maximum_impact", "max_templates"},
            "templates",
        )
        _reject_unknown(exports, {"formats", "directory"}, "exports")
        _reject_unknown(auth, {"file"}, "auth")

        allowed_ports_raw = scope.get("allowed_ports")
        allowed_ports = None
        if allowed_ports_raw is not None:
            allowed_ports = [int(item) for item in _list(allowed_ports_raw)]
            if any(port < 1 or port > 65535 for port in allowed_ports):
                raise ValueError("scope.allowed_ports values must be between 1 and 65535")
            allowed_ports = sorted(set(allowed_ports))

        maximum_impact = str(traffic.get("maximum_impact") or "active-safe").lower()
        if maximum_impact not in IMPACT_LEVELS:
            raise ValueError("Unknown traffic.maximum_impact: %s" % maximum_impact)
        template_maximum = str(templates.get("maximum_impact") or maximum_impact).lower()
        if template_maximum not in IMPACT_LEVELS:
            raise ValueError("Unknown templates.maximum_impact: %s" % template_maximum)

        api_specs = [
            _resolve_path(base_dir, item)
            for item in _unique_strings(discovery.get("api_specs"))
        ]
        template_directories = [
            _resolve_path(base_dir, item)
            for item in _unique_strings(templates.get("directories"))
        ]
        auth_value = raw.get("auth_file") or auth.get("file")

        plan = cls(
            target=str(raw.get("target")) if raw.get("target") is not None else None,
            modules=_unique_strings(raw.get("modules")),
            scope=ScopePlan(
                allowed_hosts=_unique_strings(scope.get("allowed_hosts")),
                denied_hosts=_unique_strings(scope.get("denied_hosts")),
                allowed_ports=allowed_ports,
                include_subdomains=bool(scope.get("include_subdomains", True)),
                include_paths=_unique_strings(scope.get("include_paths")),
                exclude_paths=_unique_strings(scope.get("exclude_paths")),
            ),
            discovery=DiscoveryPlan(
                enabled=bool(discovery.get("enabled", False)),
                crawl_depth=max(0, int(discovery.get("crawl_depth", 3))),
                crawl_pages=max(1, int(discovery.get("crawl_pages", 200))),
                crawl_body_bytes=max(
                    4096,
                    int(discovery.get("crawl_body_bytes", 2 * 1024 * 1024)),
                ),
                javascript_candidates=bool(discovery.get("javascript_candidates", True)),
                browser=bool(discovery.get("browser", False)),
                api_specs=[str(item) for item in api_specs if item],
            ),
            traffic=TrafficPlan(
                timeout=max(1, int(traffic.get("timeout", 10))),
                concurrency=max(1, int(traffic.get("concurrency", 5))),
                module_timeout=max(1, int(traffic.get("module_timeout", 120))),
                global_timeout=max(1, int(traffic.get("global_timeout", 600))),
                retries=max(0, int(traffic.get("retries", 3))),
                module_retries=max(0, int(traffic.get("module_retries", 1))),
                backoff=max(0.0, float(traffic.get("backoff", 0.5))),
                max_requests=max(1, int(traffic.get("max_requests", 1000))),
                maximum_impact=maximum_impact,
            ),
            project=ProjectPlan(
                database=_resolve_path(base_dir, project.get("database")),
                resume=bool(project.get("resume", False)),
                diff=bool(project.get("diff", True)),
            ),
            templates=TemplatePlan(
                directories=[str(item) for item in template_directories if item],
                maximum_impact=template_maximum,
                max_templates=max(1, int(templates.get("max_templates", 500))),
            ),
            exports=ExportPlan(
                formats=[str(item).lower() for item in _list(exports.get("formats") or ["json"])],
                directory=_resolve_path(base_dir, exports.get("directory")),
            ),
            auth_file=_resolve_path(base_dir, auth_value),
            metadata=dict(raw.get("metadata") or {}),
            source_path=expanded_path,
        )
        plan.validate()
        return plan

    def validate(self) -> None:
        supported_exports = {"json", "jsonl", "sarif", "csv", "html"}
        unknown = sorted(set(self.exports.formats) - supported_exports)
        if unknown:
            raise ValueError("Unsupported export format(s): %s" % ", ".join(unknown))
        if self.discovery.browser and not self.discovery.enabled:
            raise ValueError("Browser discovery requires discovery.enabled=true")
        if self.templates.maximum_impact not in IMPACT_LEVELS:
            raise ValueError("Invalid template impact policy")
        if not impact_allowed(self.templates.maximum_impact, self.traffic.maximum_impact):
            raise ValueError(
                "Template impact policy cannot exceed the scan traffic maximum impact"
            )
        if self.project.resume and not self.project.database:
            raise ValueError("project.resume=true requires project.database")

    def public_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "modules": list(self.modules),
            "scope": {
                "allowed_hosts": list(self.scope.allowed_hosts),
                "denied_hosts": list(self.scope.denied_hosts),
                "allowed_ports": self.scope.allowed_ports,
                "include_subdomains": self.scope.include_subdomains,
                "include_paths": list(self.scope.include_paths),
                "exclude_paths": list(self.scope.exclude_paths),
            },
            "discovery": {
                "enabled": self.discovery.enabled,
                "crawl_depth": self.discovery.crawl_depth,
                "crawl_pages": self.discovery.crawl_pages,
                "crawl_body_bytes": self.discovery.crawl_body_bytes,
                "javascript_candidates": self.discovery.javascript_candidates,
                "browser": self.discovery.browser,
                "api_specs": list(self.discovery.api_specs),
            },
            "traffic": {
                "timeout": self.traffic.timeout,
                "concurrency": self.traffic.concurrency,
                "module_timeout": self.traffic.module_timeout,
                "global_timeout": self.traffic.global_timeout,
                "retries": self.traffic.retries,
                "module_retries": self.traffic.module_retries,
                "backoff": self.traffic.backoff,
                "max_requests": self.traffic.max_requests,
                "maximum_impact": self.traffic.maximum_impact,
            },
            "project": {
                "database": self.project.database,
                "resume": self.project.resume,
                "diff": self.project.diff,
            },
            "templates": {
                "directories": list(self.templates.directories),
                "maximum_impact": self.templates.maximum_impact,
                "max_templates": self.templates.max_templates,
            },
            "exports": {
                "formats": list(self.exports.formats),
                "directory": self.exports.directory,
            },
            "auth_file": "[configured]" if self.auth_file else None,
            "metadata": dict(self.metadata),
            "source_path": self.source_path,
        }
