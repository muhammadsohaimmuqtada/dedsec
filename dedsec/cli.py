import os
import sys
import threading
from typing import Dict, List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from dedsec import __version__
from dedsec.core.banner import print_banner
from dedsec.core.contracts import ScanConfig
from dedsec.core.correlator import FindingsCorrelator
from dedsec.core.exporters import export_report
from dedsec.core.health import probe_target_connectivity
from dedsec.core.module_registry import MODULES, module_map
from dedsec.core.orchestrator import PerThreadCapture, run_modules
from dedsec.core.plugin_manager import PluginManager
from dedsec.core.report import generate_report
from dedsec.core.research_pipeline import ResearchPipeline
from dedsec.core.runtime import ScanContext
from dedsec.core.scan_plan import ScanPlan, impact_allowed
from dedsec.core.utils import configure_http_session, error, normalize_target

MODULE_MAP = module_map()

MARKET_PROFILE_MODULES = [
    "waf", "tech", "dns", "geo", "hosting", "ssl", "redirect", "robots",
    "ports", "whois", "subdomains", "js", "exposures", "cors", "csp",
    "ratelimit", "clickjacking", "email", "vhost", "api_schema",
    "http_methods", "security_policy",
]


def _validate_modules(modules: List[str], available: Optional[Dict[str, tuple]] = None):
    available_map = available or MODULE_MAP
    normalized = []
    for module in modules:
        key = module.strip().lower()
        if key not in available_map and key != "all":
            raise typer.BadParameter(
                f"Unknown module '{module}'. Valid values: all, {', '.join(available_map.keys())}"
            )
        normalized.append(key)
    return normalized


def _version_callback(value: bool):
    if value:
        typer.echo(f"DEDSEC v{__version__}")
        raise typer.Exit()


def _plan_value(current, default, planned):
    if planned is None:
        return current
    return planned if current == default else current


def _parse_formats(value: str) -> List[str]:
    formats = [item.strip().lower() for item in (value or "").replace(";", ",").split(",") if item.strip()]
    supported = {"json", "jsonl", "sarif", "csv", "html"}
    unknown = sorted(set(formats) - supported)
    if unknown:
        raise typer.BadParameter("Unsupported export format(s): %s" % ", ".join(unknown))
    return formats


def scan(
    url: str = typer.Argument("", help="Target URL (e.g., https://example.com)"),
    modules: str = typer.Option(
        "all", "--modules", "-m", help="Modules to run (comma-separated or legacy space-separated)"
    ),
    legacy_modules: Optional[List[str]] = typer.Argument(None, hidden=True),
    timeout: int = typer.Option(
        10,
        "--timeout",
        min=1,
        help="Total logical HTTP request deadline in seconds, including retries/backoff",
    ),
    concurrency: int = typer.Option(5, "--concurrency", min=1, help="Maximum concurrent module processes"),
    threads: Optional[int] = typer.Option(None, "--threads", min=1, help="Deprecated alias for --concurrency"),
    module_timeout: int = typer.Option(
        120, "--module-timeout", min=1, help="Hard per-module process deadline in seconds"
    ),
    global_timeout: int = typer.Option(
        600, "--global-timeout", min=1, help="Hard overall scan deadline in seconds"
    ),
    retries: int = typer.Option(
        3,
        "--retries",
        min=0,
        help="HTTP retries inside the total logical request deadline",
    ),
    module_retries: int = typer.Option(
        1, "--module-retries", min=0, help="Retry whole modules after classified transient failure"
    ),
    backoff: float = typer.Option(0.5, "--backoff", min=0.0, help="HTTP/module retry backoff factor"),
    max_requests: int = typer.Option(
        1000, "--max-requests", min=1, help="Shared target HTTP request budget"
    ),
    root_only: bool = typer.Option(False, "--root-only", help="Restrict target HTTP traffic to the root host"),
    preflight_timeout: float = typer.Option(
        3.0,
        "--preflight-timeout",
        min=0.1,
        help="TCP reachability timeout for each of two root-target preflight attempts",
    ),
    skip_preflight: bool = typer.Option(
        False,
        "--skip-preflight",
        help="Skip the bounded root-target TCP preflight",
    ),
    plan_file: Optional[str] = typer.Option(
        None,
        "--plan",
        help="Load a reproducible YAML/JSON scan plan",
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable bounded application crawling and request-corpus discovery",
    ),
    crawl_depth: int = typer.Option(3, "--crawl-depth", min=0, help="Maximum static/browser crawl depth"),
    crawl_pages: int = typer.Option(200, "--crawl-pages", min=1, help="Maximum static crawl pages"),
    auth_file: Optional[str] = typer.Option(
        None,
        "--auth",
        help="Researcher-supplied YAML/JSON authentication profile",
    ),
    api_spec: Optional[List[str]] = typer.Option(
        None,
        "--api-spec",
        help="Import a local OpenAPI/Swagger file into the request corpus; repeatable",
    ),
    project: Optional[str] = typer.Option(
        None,
        "--project",
        help="SQLite project database for history, diff, and resume",
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume knowledge from the latest project checkpoint"),
    template_dir: Optional[List[str]] = typer.Option(
        None,
        "--template-dir",
        help="Load declarative DEDSEC checks from a directory; repeatable",
    ),
    browser: bool = typer.Option(
        False,
        "--browser",
        help="Enable optional bounded Playwright SPA discovery",
    ),
    audit_inputs: bool = typer.Option(
        False,
        "--audit-inputs",
        help="Run bounded controlled query-reflection coverage probes; observations only",
    ),
    audit_max_requests: int = typer.Option(
        100,
        "--audit-max-requests",
        min=1,
        help="Maximum request-corpus entries considered by input audit",
    ),
    audit_max_points: int = typer.Option(
        250,
        "--audit-max-points",
        min=1,
        help="Maximum insertion points considered by input audit",
    ),
    max_impact: str = typer.Option(
        "active-safe",
        "--max-impact",
        help="Maximum impact class: passive, normal, active-safe, state-changing, high-impact",
    ),
    export_formats: str = typer.Option(
        "",
        "--export",
        help="Additional report formats: json,jsonl,sarif,csv,html",
    ),
    export_dir: Optional[str] = typer.Option(
        None,
        "--export-dir",
        help="Directory for additional report formats",
    ),
    output: Optional[str] = typer.Option(None, "--output", help="Save schema 3.0 report to JSON file"),
    evidence_dir: Optional[str] = typer.Option(
        None, "--evidence-dir", help="Persist redacted per-module evidence artifacts"
    ),
    json_output: bool = typer.Option(False, "--json", help="Print schema 3.0 report as JSON"),
    market: bool = typer.Option(
        False,
        "--market",
        help="Run the curated mixed-impact profile; review authorization before use",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
):
    print_banner()
    console = Console()

    plan = None
    if plan_file:
        try:
            plan = ScanPlan.load(plan_file)
        except Exception as exc:
            error("Invalid scan plan: %s" % exc)
            raise typer.Exit(code=2)

    if threads is not None:
        concurrency = threads

    if plan is not None:
        if not url and plan.target:
            url = str(plan.target)
        timeout = _plan_value(timeout, 10, plan.traffic.timeout)
        concurrency = _plan_value(concurrency, 5, plan.traffic.concurrency)
        module_timeout = _plan_value(module_timeout, 120, plan.traffic.module_timeout)
        global_timeout = _plan_value(global_timeout, 600, plan.traffic.global_timeout)
        retries = _plan_value(retries, 3, plan.traffic.retries)
        module_retries = _plan_value(module_retries, 1, plan.traffic.module_retries)
        backoff = _plan_value(backoff, 0.5, plan.traffic.backoff)
        max_requests = _plan_value(max_requests, 1000, plan.traffic.max_requests)
        max_impact = _plan_value(max_impact, "active-safe", plan.traffic.maximum_impact)
        deep = bool(deep or plan.discovery.enabled)
        browser = bool(browser or plan.discovery.browser)
        if crawl_depth == 3:
            crawl_depth = plan.discovery.crawl_depth
        if crawl_pages == 200:
            crawl_pages = plan.discovery.crawl_pages
        auth_file = auth_file or plan.auth_file
        project = project or plan.project.database
        resume = bool(resume or plan.project.resume)
        api_spec = list(api_spec or []) + list(plan.discovery.api_specs)
        template_dir = list(template_dir or []) + list(plan.templates.directories)
        if not export_formats and plan.exports.formats:
            export_formats = ",".join(plan.exports.formats)
        export_dir = export_dir or plan.exports.directory

    if not url:
        error("Target URL is required unless provided by --plan")
        raise typer.Exit(code=2)

    max_impact = (max_impact or "active-safe").lower()
    try:
        impact_allowed("passive", max_impact)
    except ValueError as exc:
        error(str(exc))
        raise typer.Exit(code=2)
    if audit_inputs and not impact_allowed("active-safe", max_impact):
        error("--audit-inputs requires --max-impact active-safe or higher")
        raise typer.Exit(code=2)
    if resume and not project:
        error("--resume requires --project")
        raise typer.Exit(code=2)

    plugin_manager = PluginManager()
    plugin_manager.discover_entry_points()
    execution_map = dict(MODULE_MAP)
    execution_map.update(plugin_manager.get_registered_plugins())

    configure_http_session(
        total_retries=retries,
        backoff_factor=backoff,
        pool_connections=max(concurrency * 4, 10),
        pool_maxsize=max(concurrency * 8, 20),
    )
    try:
        normalized_url, domain = normalize_target(url)
    except ValueError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    tokens = [token.strip() for token in (modules or "all").replace(",", " ").split() if token.strip()]
    tokens.extend(token.strip() for token in (legacy_modules or []) if token and token.strip())
    if plan is not None and modules == "all" and plan.modules:
        tokens = list(plan.modules)
    module_args = _validate_modules(tokens or ["all"], execution_map)
    selected = MARKET_PROFILE_MODULES if market else (
        list(execution_map.keys()) if "all" in module_args else module_args
    )

    plugin_metadata = plugin_manager.metadata()
    blocked = []
    for key in selected:
        if key in MODULES:
            impact = MODULES[key].impact_class
        else:
            impact = str(plugin_metadata.get(key, {}).get("impact_class") or "normal")
        if not impact_allowed(impact, max_impact):
            blocked.append("%s(%s)" % (key, impact))
    if blocked:
        error(
            "Selected module impact exceeds --max-impact %s: %s"
            % (max_impact, ", ".join(blocked))
        )
        raise typer.Exit(code=2)

    include_subdomains = not root_only
    allowed_hosts = None
    denied_hosts = None
    allowed_ports = None
    include_paths = None
    exclude_paths = None
    if plan is not None:
        include_subdomains = bool(plan.scope.include_subdomains and not root_only)
        allowed_hosts = plan.scope.allowed_hosts or None
        denied_hosts = plan.scope.denied_hosts or None
        allowed_ports = plan.scope.allowed_ports
        include_paths = plan.scope.include_paths or None
        exclude_paths = plan.scope.exclude_paths or None

    config = ScanConfig(
        timeout=timeout,
        concurrency=concurrency,
        module_timeout=module_timeout,
        global_timeout=global_timeout,
        retries=retries,
        backoff=backoff,
        pool_connections=max(concurrency * 4, 10),
        pool_maxsize=max(concurrency * 8, 20),
        module_retries=module_retries,
        evidence_dir=evidence_dir,
    )
    scan_context = ScanContext.build(
        target_url=normalized_url,
        domain=domain,
        timeout=timeout,
        evidence_dir=evidence_dir,
        max_requests=max_requests,
        include_subdomains=include_subdomains,
        allowed_hosts=allowed_hosts,
        denied_hosts=denied_hosts,
        allowed_ports=allowed_ports,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
    )
    evidence_store = scan_context.evidence

    if skip_preflight:
        preflight = {
            "skipped": True,
            "host": domain,
            "tcp": "not_checked",
            "attempts": 0,
        }
    else:
        preflight = probe_target_connectivity(
            normalized_url,
            health=scan_context.target_health,
            timeout=min(float(timeout), float(preflight_timeout)),
            attempts=2,
        )
        preflight["skipped"] = False

    pipeline = ResearchPipeline(scan_context)
    try:
        research = pipeline.prepare(
            plan=plan,
            deep=deep,
            auth_file=auth_file,
            api_specs=api_spec,
            project_path=project,
            resume=resume,
            template_dirs=template_dir,
            browser=browser,
            crawl_depth=crawl_depth,
            crawl_pages=crawl_pages,
            audit_inputs=audit_inputs,
            audit_max_requests=audit_max_requests,
            audit_max_insertion_points=audit_max_points,
        )
    except Exception as exc:
        if pipeline.project_store is not None:
            pipeline.project_store.close()
            pipeline.project_store = None
        scan_context.close()
        error("Research pipeline initialization failed: %s" % exc)
        raise typer.Exit(code=2)

    info_table = Table(show_header=False, title="Scan Configuration")
    info_table.add_column("key", style="cyan", no_wrap=True)
    info_table.add_column("value", style="white")
    info_table.add_row("Target URL", normalized_url)
    info_table.add_row("Domain", domain)
    info_table.add_row("Modules", ", ".join(selected))
    info_table.add_row("Request deadline", f"{timeout}s total")
    info_table.add_row("Concurrency", str(min(config.concurrency, len(selected))))
    info_table.add_row("Module retries", str(module_retries))
    info_table.add_row("Scan ID", evidence_store.scan_id)
    info_table.add_row("Maximum impact", max_impact)
    info_table.add_row("Target HTTP budget", str(max_requests))
    info_table.add_row("Hard module timeout", f"{module_timeout}s")
    info_table.add_row("Hard global timeout", f"{global_timeout}s")
    info_table.add_row(
        "Target preflight",
        "skipped" if skip_preflight else f"{preflight.get('tcp')} ({preflight.get('attempts', 0)} attempt(s))",
    )
    info_table.add_row("Deep discovery", "enabled" if deep else "disabled")
    info_table.add_row("Input audit", "enabled" if audit_inputs else "disabled")
    if auth_file:
        auth_meta = research.metadata.get("authentication") or {}
        info_table.add_row(
            "Identity",
            "%s (%s)" % (
                auth_meta.get("label", "configured"),
                "verified" if auth_meta.get("verified") else "not verified",
            ),
        )
    if project:
        info_table.add_row("Project", os.path.abspath(os.path.expanduser(project)))
    if evidence_dir:
        info_table.add_row("Evidence dir", evidence_dir)
    console.print(info_table)

    capture = PerThreadCapture(sys.stdout)
    results = {}
    module_results = []
    progress_lock = threading.Lock()
    last_status = {}

    def _on_update(module_result):
        previous = last_status.get(module_result.module)
        last_status[module_result.module] = module_result.status
        if previous == module_result.status:
            return
        with progress_lock:
            if module_result.status == "running":
                capture._real.write(f"[>] {module_result.module}: started\n")
            else:
                capture._real.write(
                    f"[>] {module_result.module}: {module_result.status.upper()} "
                    f"({module_result.duration:.2f}s)\n"
                )
            capture._real.flush()

    report_data = None
    try:
        sys.stdout = capture
        try:
            results, module_results = run_modules(
                selected_modules=selected,
                module_map=execution_map,
                url=normalized_url,
                domain=domain,
                config=config,
                on_update=_on_update,
                evidence_store=evidence_store,
                scan_context=scan_context,
            )
        finally:
            sys.stdout = capture._real

        pipeline.ingest_module_results(module_results)
        project_diff = None
        if project and (plan is None or plan.project.diff):
            project_diff = pipeline.compute_project_diff()

        for item in module_results:
            if item.output:
                capture._real.write(item.output)

        summary = Table(title="Module Status Summary")
        summary.add_column("Module", style="cyan", no_wrap=True)
        summary.add_column("Status", no_wrap=True)
        summary.add_column("Attempts", justify="right")
        summary.add_column("Duration (s)", justify="right")
        for item in module_results:
            style = {
                "success": "green",
                "partial": "yellow",
                "inconclusive": "yellow",
                "failed": "red",
                "timeout": "yellow",
                "aborted": "yellow",
            }.get(item.status, "white")
            summary.add_row(
                item.module,
                Text(item.status.upper(), style=style),
                str(item.attempts),
                f"{item.duration:.2f}",
            )
        console.print(summary)

        correlated = FindingsCorrelator().correlate(module_results)
        report_data = generate_report(
            normalized_url,
            domain,
            results,
            json_output=json_output,
            output_file=output,
            module_results=module_results,
            evidence_store=evidence_store,
            correlated=correlated,
            workspace=pipeline.workspace,
            project_diff=project_diff,
            research_metadata=research.metadata,
            runtime_metadata={
                "target_http_requests_used": scan_context.request_budget.requests_used,
                "target_http_request_budget": max_requests,
                "request_deadline_seconds": timeout,
                "module_timeout_seconds": module_timeout,
                "global_timeout_seconds": global_timeout,
                "concurrency": min(config.concurrency, len(selected)),
                "scope_mode": "root-only" if root_only else "configured",
                "maximum_impact": max_impact,
                "preflight": preflight,
                "target_health": scan_context.target_health.snapshot(),
                "identity_id": scan_context.identity_id,
                "external_intelligence_http_counted_in_target_budget": False,
                "raw_socket_and_dns_operations_counted_in_target_http_budget": False,
            },
        )

        if export_formats:
            formats = _parse_formats(export_formats)
            destination = export_dir or "dedsec-exports"
            exported = export_report(
                report_data,
                destination,
                formats,
                basename=evidence_store.scan_id,
            )
            for format_name, path in sorted(exported.items()):
                capture._real.write("[+] %s export: %s\n" % (format_name.upper(), path))
            capture._real.flush()

        pipeline.finalize(report=report_data)
    finally:
        sys.stdout = capture._real
        if pipeline.project_store is not None:
            pipeline.project_store.close()
            pipeline.project_store = None
        scan_context.close()


def main():
    if "--version" in sys.argv[1:] and all(arg.startswith("-") for arg in sys.argv[1:]):
        typer.echo(f"DEDSEC v{__version__}")
        return
    typer.run(scan)


if __name__ == "__main__":
    main()
