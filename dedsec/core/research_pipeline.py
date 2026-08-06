import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, Sequence

from dedsec.core.api_import import OpenAPIImporter
from dedsec.core.audit import AuditConfig, AuditEngine
from dedsec.core.auth import AuthManager, AuthProfile
from dedsec.core.browser import BrowserCrawlConfig, BrowserCrawler, BrowserUnavailable
from dedsec.core.contracts import ModuleResult
from dedsec.core.crawler import CrawlConfig, CrawlerEngine
from dedsec.core.network_paths import probe_target_paths
from dedsec.core.project_store import ProjectStore
from dedsec.core.scan_plan import IMPACT_LEVELS, ScanPlan, impact_allowed
from dedsec.core.templates import TemplateRepository, TemplateRunner
from dedsec.core.workspace import Observation, ResearchWorkspace


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _lower_impact(first: str, second: str) -> str:
    if first not in IMPACT_LEVELS:
        raise ValueError("Unknown impact class: %s" % first)
    if second not in IMPACT_LEVELS:
        raise ValueError("Unknown impact class: %s" % second)
    return first if IMPACT_LEVELS[first] <= IMPACT_LEVELS[second] else second


@dataclass
class ResearchPipelineResult:
    workspace: ResearchWorkspace
    metadata: Dict[str, Any] = field(default_factory=dict)
    project_diff: Optional[Dict[str, Any]] = None


class ResearchPipeline:
    """Cross-cutting discovery and knowledge layer around the legacy module set."""

    def __init__(self, context):
        self.context = context
        self.workspace = ResearchWorkspace(context.scan_id, context.target_url, context.domain)
        self.workspace.metadata["generated_at"] = _utc_now()
        self.metadata: Dict[str, Any] = {}
        self.project_store: Optional[ProjectStore] = None
        self.project_diff: Optional[Dict[str, Any]] = None

    def _sync_metadata(self) -> None:
        self.workspace.metadata["pipeline"] = dict(self.metadata)

    def _checkpoint(self, stage: str) -> None:
        if self.project_store is None:
            return
        self.metadata["last_checkpoint_stage"] = stage
        self._sync_metadata()
        self.project_store.checkpoint(self.workspace)

    def _configure_project(self, project_path: Optional[str], resume: bool) -> None:
        if not project_path:
            return
        self.project_store = ProjectStore(project_path)
        self.metadata["project_database"] = self.project_store.path
        if resume:
            checkpoint = self.project_store.latest_checkpoint(self.context.domain)
            if checkpoint:
                self.workspace.merge_snapshot(checkpoint)
                inherited_scan_id = checkpoint.get("scan_id")
                self.workspace.scan_id = self.context.scan_id
                self.workspace.coverage.requests_discovered = len(self.workspace.requests)
                self.workspace.coverage.insertion_points_discovered = sum(
                    len(request.insertion_points) for request in self.workspace.requests.values()
                )
                self.workspace.coverage.requests_observed = 0
                self.workspace.coverage.requests_audited = 0
                self.workspace.coverage.requests_skipped = 0
                self.workspace.coverage.insertion_points_audited = 0
                self.workspace.coverage.insertion_points_skipped = 0
                self.workspace.coverage.skipped_reasons = {}
                self.workspace.metadata["generated_at"] = _utc_now()
                self.metadata["resumed_from_scan_id"] = inherited_scan_id
                self.metadata["resumed_requests"] = len(self.workspace.requests)
                self.metadata["resumed_insertion_points"] = sum(
                    len(request.insertion_points) for request in self.workspace.requests.values()
                )

    def _configure_identity(self, auth_file: Optional[str]) -> Dict[str, str]:
        if not auth_file:
            return dict(getattr(self.context, "default_headers", {}) or {})
        profile = AuthProfile.load(auth_file)
        prepared = AuthManager(self.context).prepare(profile)
        self.workspace.add_identity(prepared.identity)
        self.metadata["authentication"] = {
            "identity_id": prepared.identity.id,
            "label": prepared.identity.label,
            "kind": prepared.identity.kind,
            "role": prepared.identity.role,
            "tenant": prepared.identity.tenant,
            "verified": prepared.verified,
            "verification": prepared.verification,
        }
        self.context.default_headers = dict(prepared.headers)
        self.context.identity_id = prepared.identity.id
        return dict(prepared.headers)

    def prepare(
        self,
        plan: Optional[ScanPlan] = None,
        deep: bool = False,
        auth_file: Optional[str] = None,
        api_specs: Optional[Sequence[str]] = None,
        project_path: Optional[str] = None,
        resume: bool = False,
        template_dirs: Optional[Sequence[str]] = None,
        browser: bool = False,
        crawl_depth: Optional[int] = None,
        crawl_pages: Optional[int] = None,
        audit_inputs: bool = False,
        audit_max_requests: int = 100,
        audit_max_insertion_points: int = 250,
        maximum_impact: str = "active-safe",
    ) -> ResearchPipelineResult:
        maximum_impact = str(maximum_impact or "active-safe").lower()
        if maximum_impact not in IMPACT_LEVELS:
            raise ValueError("Unknown maximum impact class: %s" % maximum_impact)

        if plan is not None:
            deep = bool(deep or plan.discovery.enabled)
            auth_file = auth_file or plan.auth_file
            api_specs = list(api_specs or []) + list(plan.discovery.api_specs)
            project_path = project_path or plan.project.database
            resume = bool(resume or plan.project.resume)
            template_dirs = list(template_dirs or []) + list(plan.templates.directories)
            browser = bool(browser or plan.discovery.browser)
            if crawl_depth is None:
                crawl_depth = plan.discovery.crawl_depth
            if crawl_pages is None:
                crawl_pages = plan.discovery.crawl_pages
            self.workspace.metadata["scan_plan"] = plan.public_dict()

        self.metadata["maximum_impact"] = maximum_impact
        if (deep or browser or auth_file) and not impact_allowed("normal", maximum_impact):
            raise ValueError(
                "Deep discovery, browser discovery, and authentication require maximum impact normal or higher"
            )
        if audit_inputs and not impact_allowed("active-safe", maximum_impact):
            raise ValueError("Input auditing requires maximum impact active-safe or higher")

        self._configure_project(project_path, resume)
        headers = self._configure_identity(auth_file)

        if impact_allowed("normal", maximum_impact):
            self.metadata["network_paths"] = probe_target_paths(
                self.context.target_url,
                timeout=min(3.0, float(self.context.timeout)),
            )
        else:
            self.metadata["network_paths"] = {
                "status": "skipped",
                "reason": "impact-policy",
                "maximum_impact": maximum_impact,
            }
        self.workspace.metadata["network_paths"] = self.metadata["network_paths"]
        self._checkpoint("prepared")

        if deep:
            config = CrawlConfig(
                max_depth=3 if crawl_depth is None else max(0, int(crawl_depth)),
                max_pages=200 if crawl_pages is None else max(1, int(crawl_pages)),
                max_body_bytes=(
                    plan.discovery.crawl_body_bytes
                    if plan is not None
                    else 2 * 1024 * 1024
                ),
                timeout=float(self.context.timeout),
                crawl_javascript_candidates=(
                    plan.discovery.javascript_candidates if plan is not None else True
                ),
            )
            crawler = CrawlerEngine(
                self.context,
                self.workspace,
                config=config,
                default_headers=headers,
            )
            self.metadata["crawler"] = crawler.crawl(self.context.target_url)
            self._checkpoint("crawler")

        specs = []
        for path in api_specs or []:
            expanded = os.path.abspath(os.path.expanduser(path))
            if expanded not in specs:
                specs.append(expanded)
        if specs:
            importer = OpenAPIImporter(
                self.context.target_url,
                scope=self.context.scope,
                default_headers=headers,
            )
            imported = []
            identity_id = getattr(self.context, "identity_id", "identity-anonymous")
            for path in specs:
                imported.append(importer.ingest_file(self.workspace, path, identity_id=identity_id))
            self.metadata["api_import"] = imported
            self._checkpoint("api-import")

        if browser:
            try:
                browser_config = BrowserCrawlConfig(
                    max_depth=2 if crawl_depth is None else min(3, max(0, int(crawl_depth))),
                    max_pages=50 if crawl_pages is None else min(100, max(1, int(crawl_pages))),
                )
                self.metadata["browser"] = BrowserCrawler(
                    self.context,
                    self.workspace,
                    browser_config,
                ).crawl(self.context.target_url, headers=headers)
            except BrowserUnavailable as exc:
                self.metadata["browser"] = {"status": "unavailable", "reason": str(exc)}
            self._checkpoint("browser")

        directories = []
        for item in template_dirs or []:
            expanded = os.path.abspath(os.path.expanduser(item))
            if expanded not in directories:
                directories.append(expanded)
        if directories:
            template_impact = maximum_impact
            if plan is not None:
                template_impact = _lower_impact(template_impact, plan.templates.maximum_impact)
            max_templates = plan.templates.max_templates if plan is not None else 500
            definitions = TemplateRepository(directories, max_templates=max_templates).load()
            self.metadata["templates"] = TemplateRunner(
                self.context,
                self.workspace,
                maximum_impact=template_impact,
            ).run(definitions)
            self._checkpoint("templates")

        if audit_inputs:
            self.metadata["audit"] = AuditEngine(
                self.context,
                self.workspace,
                AuditConfig(
                    max_requests=max(1, int(audit_max_requests)),
                    max_insertion_points=max(1, int(audit_max_insertion_points)),
                    reflection_probe=True,
                    identity_id=None,
                ),
            ).run()
            self._checkpoint("audit")

        self._sync_metadata()
        return ResearchPipelineResult(self.workspace, dict(self.metadata), self.project_diff)

    def ingest_module_results(self, module_results: Iterable[ModuleResult]) -> None:
        root_domain_id = self.workspace.add_asset("domain", self.context.domain, source="module")
        root_url_id = self.workspace.add_asset("url", self.context.target_url, source="module")

        for result in module_results:
            data = result.data or {}
            source = "module:%s" % result.module
            if result.module == "dns":
                records = data.get("records") or {}
                for address in records.get("A", []) + records.get("AAAA", []):
                    ip_id = self.workspace.add_asset("ip", str(address), source=source)
                    self.workspace.add_edge(root_domain_id, ip_id, "resolves_to", {"source": source})
                for name in records.get("NS", []):
                    host_id = self.workspace.add_asset("host", str(name).rstrip("."), source=source)
                    self.workspace.add_edge(root_domain_id, host_id, "delegated_to", {"source": source})
                for name in records.get("MX", []):
                    parts = str(name).split()
                    host = parts[-1].rstrip(".") if parts else str(name).rstrip(".")
                    host_id = self.workspace.add_asset("host", host, source=source)
                    self.workspace.add_edge(root_domain_id, host_id, "mail_exchanger", {"source": source})
                for name in records.get("CNAME", []):
                    host_id = self.workspace.add_asset("host", str(name).rstrip("."), source=source)
                    self.workspace.add_edge(root_domain_id, host_id, "canonical_name", {"source": source})

            elif result.module == "subdomains":
                for item in data.get("discovered") or []:
                    if not isinstance(item, dict) or not item.get("subdomain"):
                        continue
                    host_id = self.workspace.add_asset(
                        "host",
                        item["subdomain"],
                        attributes={
                            "resolved": bool(item.get("resolved")),
                            "alive": bool(item.get("alive")),
                            "resolution_state": item.get("resolution_state"),
                        },
                        source=source,
                    )
                    self.workspace.add_edge(root_domain_id, host_id, "has_subdomain", {"source": source})
                    if item.get("ip"):
                        ip_id = self.workspace.add_asset("ip", item["ip"], source=source)
                        self.workspace.add_edge(host_id, ip_id, "resolves_to", {"source": source})
                for item in data.get("alive") or []:
                    if isinstance(item, dict) and item.get("url"):
                        url_id = self.workspace.add_asset(
                            "url",
                            item["url"],
                            attributes={"status_code": item.get("status")},
                            source=source,
                        )
                        host_id = self.workspace.add_asset("host", item.get("subdomain", ""), source=source)
                        self.workspace.add_edge(host_id, url_id, "serves", {"source": source})

            elif result.module == "ports":
                port_states = self.workspace.metadata.setdefault("port_states", {})
                for state_key in ("open", "closed", "filtered", "unreachable", "errors"):
                    for item in data.get(state_key) or []:
                        if not isinstance(item, dict) or item.get("port") is None:
                            continue
                        key = "%s/tcp" % item["port"]
                        port_states[key] = "error" if state_key == "errors" else state_key
                        if state_key == "open":
                            service_id = self.workspace.add_asset(
                                "service",
                                "%s:%s/tcp" % (self.context.domain, item["port"]),
                                attributes={
                                    "port": item.get("port"),
                                    "service": item.get("service"),
                                    "state": "open",
                                    "banner": item.get("banner"),
                                    "http_headers": item.get("http_headers") or {},
                                },
                                source=source,
                            )
                            self.workspace.add_edge(root_domain_id, service_id, "exposes_service", {"source": source})

            elif result.module == "tech":
                for category in (
                    "languages",
                    "servers",
                    "cms",
                    "js_frameworks",
                    "cdn",
                    "analytics",
                ):
                    for item in data.get(category) or []:
                        if not isinstance(item, dict) or not item.get("name"):
                            continue
                        tech_id = self.workspace.add_asset(
                            "technology",
                            "%s:%s" % (category, item["name"]),
                            attributes={
                                "name": item["name"],
                                "category": category,
                                "confidence": item.get("confidence"),
                                "evidence": item.get("evidence") or [],
                            },
                            source=source,
                        )
                        self.workspace.add_edge(root_url_id, tech_id, "uses_technology", {"source": source})

            elif result.module == "hosting":
                for item in data.get("ips") or []:
                    if not isinstance(item, dict) or not item.get("ip"):
                        continue
                    ip_id = self.workspace.add_asset(
                        "ip",
                        item["ip"],
                        attributes={
                            "reverse_dns": item.get("reverse_dns"),
                            "metadata": item.get("metadata") or {},
                        },
                        source=source,
                    )
                    self.workspace.add_edge(root_domain_id, ip_id, "resolves_to", {"source": source})
                    reverse = item.get("reverse_dns")
                    if reverse:
                        host_id = self.workspace.add_asset("host", reverse, source=source)
                        self.workspace.add_edge(ip_id, host_id, "reverse_dns", {"source": source})

            elif result.module == "ssl" and data.get("cn"):
                cert_key = "%s|%s|%s" % (
                    data.get("cn"),
                    data.get("issuer"),
                    data.get("valid_until"),
                )
                cert_id = self.workspace.add_asset(
                    "certificate",
                    cert_key,
                    attributes={
                        "cn": data.get("cn"),
                        "issuer": data.get("issuer"),
                        "sans": data.get("sans") or [],
                        "valid_from": data.get("valid_from"),
                        "valid_until": data.get("valid_until"),
                        "protocol": data.get("protocol"),
                        "cipher": data.get("cipher"),
                    },
                    source=source,
                )
                self.workspace.add_edge(root_domain_id, cert_id, "presents_certificate", {"source": source})
                for san in data.get("sans") or []:
                    host_id = self.workspace.add_asset("host", san, source=source)
                    self.workspace.add_edge(cert_id, host_id, "certificate_for", {"source": source})

            if result.status in {"partial", "inconclusive", "failed", "timeout", "aborted"}:
                observation = Observation.build(
                    category="coverage",
                    title="Module did not produce a fully conclusive result",
                    classification="coverage-observation",
                    severity="INFO",
                    confidence="observed",
                    evidence={
                        "module": result.module,
                        "status": result.status,
                        "failure_class": result.failure_class,
                        "error": result.error,
                    },
                    source=source,
                )
                self.workspace.add_observation(observation)

        self._sync_metadata()
        self._checkpoint("modules")

    def compute_project_diff(self) -> Optional[Dict[str, Any]]:
        if self.project_store is None:
            self.project_diff = None
        else:
            self.project_diff = self.project_store.diff_workspace(self.workspace)
        return self.project_diff

    def finalize(self, report: Optional[Dict[str, Any]] = None) -> ResearchPipelineResult:
        self._sync_metadata()
        if self.project_store is not None:
            if self.project_diff is None:
                self.project_diff = self.project_store.diff_workspace(self.workspace)
            self.project_store.save_workspace(self.workspace, status="complete", report=report)
            self.project_store.close()
            self.project_store = None
        return ResearchPipelineResult(
            workspace=self.workspace,
            metadata=dict(self.metadata),
            project_diff=self.project_diff,
        )
