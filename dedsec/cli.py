import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from dedsec import __version__
from dedsec.core.banner import print_banner
from dedsec.core.contracts import ScanConfig
from dedsec.core.correlator import FindingsCorrelator
from dedsec.core.evidence import EvidenceStore
from dedsec.core.orchestrator import PerThreadCapture, run_modules
from dedsec.core.report import generate_report
from dedsec.core.utils import configure_http_session, error, normalize_target

MODULE_MAP = {
    "waf": ("dedsec.modules.waf_detect", "🛡️  WAF Detection"),
    "tech": ("dedsec.modules.tech_fingerprint", "🌐 Technology Fingerprinting"),
    "dns": ("dedsec.modules.dns_recon", "🔍 DNS Reconnaissance"),
    "geo": ("dedsec.modules.ip_geo", "🌍 IP & GeoLocation"),
    "ssl": ("dedsec.modules.ssl_analysis", "🔒 SSL/TLS Analysis"),
    "headers": ("dedsec.modules.header_audit", "📋 HTTP Header Audit"),
    "redirect": ("dedsec.modules.open_redirect", "🚪 Open Redirect Check"),
    "robots": ("dedsec.modules.robots_sitemap", "🤖 Robots & Sitemap"),
    "cookies": ("dedsec.modules.cookie_audit", "🍪 Cookie Audit"),
    "ports": ("dedsec.modules.port_scan", "📡 Port Scan"),
    "whois": ("dedsec.modules.whois_lookup", "🕵️  WHOIS Lookup"),
    "subdomains": ("dedsec.modules.subdomain_enum", "🌐 Subdomain Enumeration"),
    "js": ("dedsec.modules.js_extraction", "📜 JS & Endpoint Extraction"),
    "hosting": ("dedsec.modules.hosting_intel", "🏢 Hosting Intelligence"),
    "exposures": ("dedsec.modules.exposure_checks", "🚨 Common Exposure Checks"),
    "cors": ("dedsec.modules.cors_check", "🌐 CORS Misconfiguration Check"),
    "csp": ("dedsec.modules.csp_analyzer", "🛡️  CSP Deep Analyzer"),
    "ratelimit": ("dedsec.modules.rate_limit_check", "📡 Rate Limit Detection Check"),
    "clickjacking": ("dedsec.modules.clickjacking_check", "🖼️  Clickjacking Check"),
    "email": ("dedsec.modules.email_security", "✉️  Email Security Audit"),
    "vhost": ("dedsec.modules.vhost_finder", "🖥️  Virtual Host Finder"),
    "api_schema": ("dedsec.modules.api_schema_scanner", "📜 API & OpenAPI Schema Scanner"),
    "http_methods": ("dedsec.modules.http_methods_audit", "🛠️  Dangerous HTTP Methods Audit"),
    "security_policy": ("dedsec.modules.security_policy_audit", "📄 Security Policy Audit"),
}

MARKET_PROFILE_MODULES = [
    "waf",
    "tech",
    "dns",
    "geo",
    "hosting",
    "ssl",
    "redirect",
    "robots",
    "ports",
    "whois",
    "subdomains",
    "js",
    "exposures",
    "cors",
    "csp",
    "ratelimit",
    "clickjacking",
    "email",
    "vhost",
    "api_schema",
    "http_methods",
    "security_policy",
]


def _validate_modules(modules: List[str]):
    normalized = []
    for module in modules:
        key = module.strip().lower()
        if key not in MODULE_MAP and key != "all":
            raise typer.BadParameter(
                f"Unknown module '{module}'. Valid values: all, {', '.join(MODULE_MAP.keys())}"
            )
        normalized.append(key)
    return normalized


def _version_callback(value: bool):
    if value:
        typer.echo(f"DEDSEC v{__version__}")
        raise typer.Exit()


def scan(
    url: str = typer.Argument(..., help="Target URL (e.g., https://example.com)"),
    modules: str = typer.Option(
        "all", "--modules", "-m", help="Modules to run (comma-separated or legacy space-separated)"
    ),
    legacy_modules: Optional[List[str]] = typer.Argument(None, hidden=True),
    timeout: int = typer.Option(10, "--timeout", min=1, help="Request timeout in seconds"),
    concurrency: int = typer.Option(
        5, "--concurrency", min=1, help="Bounded parallel module concurrency"
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", min=1, help="Deprecated alias for --concurrency"
    ),
    module_timeout: Optional[int] = typer.Option(
        None, "--module-timeout", min=1, help="Per-module timeout in seconds"
    ),
    global_timeout: Optional[int] = typer.Option(
        None, "--global-timeout", min=1, help="Global scan timeout in seconds"
    ),
    retries: int = typer.Option(
        3, "--retries", min=0, help="HTTP retries with exponential backoff"
    ),
    module_retries: int = typer.Option(
        1,
        "--module-retries",
        min=0,
        help="Retry whole modules only after transient/timeout failures",
    ),
    backoff: float = typer.Option(
        0.5, "--backoff", min=0.0, help="HTTP/module retry backoff factor"
    ),
    output: Optional[str] = typer.Option(None, "--output", help="Save v2 report to file (JSON)"),
    evidence_dir: Optional[str] = typer.Option(
        None,
        "--evidence-dir",
        help="Persist redacted per-module evidence artifacts to this directory",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output v2 report as JSON"),
    market: bool = typer.Option(False, "--market", help="Run curated market-ready recon profile"),
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

    if threads is not None:
        concurrency = threads

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

    modules_str = modules or "all"
    module_tokens = [
        token.strip() for token in modules_str.replace(",", " ").split() if token.strip()
    ]
    module_tokens.extend(
        token.strip() for token in (legacy_modules or []) if token and token.strip()
    )
    module_args = _validate_modules(module_tokens or ["all"])
    if market:
        selected = MARKET_PROFILE_MODULES
    else:
        selected = list(MODULE_MAP.keys()) if "all" in module_args else module_args

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
    evidence_store = EvidenceStore(artifact_dir=evidence_dir)

    info_table = Table(show_header=False, title="Scan Configuration")
    info_table.add_column("key", style="cyan", no_wrap=True)
    info_table.add_column("value", style="white")
    info_table.add_row("Target URL", normalized_url)
    info_table.add_row("Domain", domain)
    info_table.add_row("Modules", ", ".join(selected))
    info_table.add_row("Timeout", f"{timeout}s")
    info_table.add_row("Concurrency", str(min(config.concurrency, len(selected))))
    info_table.add_row("Module retries", str(module_retries))
    info_table.add_row("Scan ID", evidence_store.scan_id)
    if module_timeout:
        info_table.add_row("Module timeout", f"{module_timeout}s")
    if global_timeout:
        info_table.add_row("Global timeout", f"{global_timeout}s")
    if evidence_dir:
        info_table.add_row("Evidence dir", evidence_dir)
    console.print(info_table)

    capture = PerThreadCapture(sys.stdout)
    sys.stdout = capture
    status_rows = {}

    def _on_update(module_result):
        status_rows[module_result.module] = module_result.status

    try:
        results, module_results = run_modules(
            selected_modules=selected,
            module_map=MODULE_MAP,
            url=normalized_url,
            domain=domain,
            config=config,
            on_update=_on_update,
            evidence_store=evidence_store,
        )
    finally:
        sys.stdout = capture._real

    for item in module_results:
        if item.output:
            capture._real.write(item.output)

    summary = Table(title="Module Status Summary")
    summary.add_column("Module", style="cyan", no_wrap=True)
    summary.add_column("Status", no_wrap=True)
    summary.add_column("Attempts", justify="right")
    summary.add_column("Duration (s)", justify="right")
    for item in module_results:
        status_style = {
            "success": "green",
            "failed": "red",
            "timeout": "yellow",
            "running": "cyan",
        }.get(item.status, "white")
        summary.add_row(
            item.module,
            Text(item.status.upper(), style=status_style),
            str(item.attempts),
            f"{item.duration:.2f}",
        )
    console.print(summary)

    correlated = FindingsCorrelator().correlate(module_results)
    generate_report(
        normalized_url,
        domain,
        results,
        json_output=json_output,
        output_file=output,
        module_results=module_results,
        evidence_store=evidence_store,
        correlated=correlated,
    )


def main():
    typer.run(scan)


if __name__ == "__main__":
    main()
