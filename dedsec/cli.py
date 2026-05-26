import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from dedsec import __version__
from dedsec.core.banner import print_banner
from dedsec.core.contracts import ScanConfig
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
]

def _validate_modules(modules: List[str]):
    normalized = []
    for module in modules:
        key = module.strip().lower()
        if key not in MODULE_MAP and key != "all":
            raise typer.BadParameter(f"Unknown module '{module}'. Valid values: all, {', '.join(MODULE_MAP.keys())}")
        normalized.append(key)
    return normalized


def _version_callback(value: bool):
    if value:
        typer.echo(f"DEDSEC v{__version__}")
        raise typer.Exit()


def scan(
    url: str = typer.Argument(..., help="Target URL (e.g., https://example.com)"),
    modules: str = typer.Option("all", "--modules", "-m", help="Modules to run (comma-separated or legacy space-separated)"),
    legacy_modules: Optional[List[str]] = typer.Argument(None, hidden=True),
    timeout: int = typer.Option(10, "--timeout", min=1, help="Request timeout in seconds"),
    concurrency: int = typer.Option(5, "--concurrency", min=1, help="Bounded parallel module concurrency"),
    threads: Optional[int] = typer.Option(None, "--threads", min=1, help="Deprecated alias for --concurrency"),
    module_timeout: Optional[int] = typer.Option(None, "--module-timeout", min=1, help="Per-module timeout in seconds"),
    global_timeout: Optional[int] = typer.Option(None, "--global-timeout", min=1, help="Global scan timeout in seconds"),
    retries: int = typer.Option(3, "--retries", min=0, help="HTTP retries with exponential backoff"),
    backoff: float = typer.Option(0.5, "--backoff", min=0.0, help="HTTP retry backoff factor"),
    output: Optional[str] = typer.Option(None, "--output", help="Save report to file (JSON)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
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

    module_tokens = [token.strip() for token in modules.replace(",", " ").split() if token.strip()]
    module_tokens.extend(token.strip() for token in (legacy_modules or []) if token and token.strip())
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
    )

    info_table = Table(show_header=False, title="Scan Configuration")
    info_table.add_column("key", style="cyan", no_wrap=True)
    info_table.add_column("value", style="white")
    info_table.add_row("Target URL", normalized_url)
    info_table.add_row("Domain", domain)
    info_table.add_row("Modules", ", ".join(selected))
    info_table.add_row("Timeout", f"{timeout}s")
    info_table.add_row("Concurrency", str(min(config.concurrency, len(selected))))
    if module_timeout:
        info_table.add_row("Module timeout", f"{module_timeout}s")
    if global_timeout:
        info_table.add_row("Global timeout", f"{global_timeout}s")
    console.print(info_table)

    capture = PerThreadCapture(sys.stdout)
    sys.stdout = capture

    status_rows = {}

    def _on_update(module_result):
        if module_result.status == "running":
            status_rows[module_result.module] = "running"
        else:
            status_rows[module_result.module] = module_result.status

    results, module_results = run_modules(
        selected_modules=selected,
        module_map=MODULE_MAP,
        url=normalized_url,
        domain=domain,
        config=config,
        on_update=_on_update,
    )

    sys.stdout = capture._real

    for item in module_results:
        if item.output:
            capture._real.write(item.output)

    summary = Table(title="Module Status Summary")
    summary.add_column("Module", style="cyan", no_wrap=True)
    summary.add_column("Status", no_wrap=True)
    summary.add_column("Duration (s)", justify="right")
    for item in module_results:
        status_style = {
            "success": "green",
            "failed": "red",
            "timeout": "yellow",
            "running": "cyan",
        }.get(item.status, "white")
        summary.add_row(item.module, Text(item.status.upper(), style=status_style), f"{item.duration:.2f}")
    console.print(summary)

    generate_report(
        normalized_url,
        domain,
        results,
        json_output=json_output,
        output_file=output,
        module_results=module_results,
    )


def main():
    typer.run(scan)


if __name__ == "__main__":
    main()
