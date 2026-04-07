import argparse
import importlib
import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dedsec.core.banner import print_banner
from dedsec.core.colors import Colors
from dedsec.core.utils import get_domain, section, info, warn, error
from dedsec.core.report import generate_report
from dedsec import __version__

MODULE_MAP = {
    "waf":        ("dedsec.modules.waf_detect",      "🛡️  WAF Detection"),
    "tech":       ("dedsec.modules.tech_fingerprint", "🌐 Technology Fingerprinting"),
    "dns":        ("dedsec.modules.dns_recon",        "🔍 DNS Reconnaissance"),
    "geo":        ("dedsec.modules.ip_geo",           "🌍 IP & GeoLocation"),
    "ssl":        ("dedsec.modules.ssl_analysis",     "🔒 SSL/TLS Analysis"),
    "headers":    ("dedsec.modules.header_audit",     "📋 HTTP Header Audit"),
    "redirect":   ("dedsec.modules.open_redirect",    "🚪 Open Redirect Check"),
    "robots":     ("dedsec.modules.robots_sitemap",   "🤖 Robots & Sitemap"),
    "cookies":    ("dedsec.modules.cookie_audit",     "🍪 Cookie Audit"),
    "ports":      ("dedsec.modules.port_scan",        "📡 Port Scan"),
    "whois":      ("dedsec.modules.whois_lookup",     "🕵️  WHOIS Lookup"),
    "subdomains": ("dedsec.modules.subdomain_enum",   "🌐 Subdomain Enumeration"),
    "js":         ("dedsec.modules.js_extraction",    "📜 JS & Endpoint Extraction"),
    "hosting":    ("dedsec.modules.hosting_intel",    "🏢 Hosting Intelligence"),
    "exposures":  ("dedsec.modules.exposure_checks",  "🚨 Common Exposure Checks"),
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

_thread_buffers = threading.local()


class _PerThreadCapture:
    """Thread-safe stdout wrapper that captures writes into per-thread buffers
    so that parallel module output does not interleave on the terminal."""

    def __init__(self, real_stream):
        self._real = real_stream

    def _target(self):
        return getattr(_thread_buffers, "buf", None) or self._real

    def write(self, data):
        self._target().write(data)

    def flush(self):
        self._target().flush()

    def fileno(self):
        return self._real.fileno()

    def isatty(self):
        return self._real.isatty()


def _run_module(key, url, domain, timeout, capture):
    """Execute one reconnaissance module and return its result + buffered output."""
    module_path, label = MODULE_MAP[key]
    buf = io.StringIO()
    _thread_buffers.buf = buf
    try:
        mod = importlib.import_module(module_path)
        result = mod.run(url, domain, timeout=timeout)
    except Exception as exc:
        result = {"error": str(exc)}
        buf.write(f"{Colors.RED}[-]{Colors.RESET} Module '{key}' failed: {exc}\n")
    finally:
        _thread_buffers.buf = None
    return key, result, buf.getvalue()

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="dedsec",
        description="DEDSEC — Web Reconnaissance Framework",
    )
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=list(MODULE_MAP.keys()) + ["all"],
        default=["all"],
        metavar="{all," + ",".join(MODULE_MAP.keys()) + "}",
        help="Modules to run (default: all)",
    )
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel module threads (default: 5)")
    parser.add_argument("--output", default=None, help="Save report to file")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument(
        "--market",
        action="store_true",
        help="Run curated market-ready recon profile (high-signal modules, excludes header-only checks)",
    )
    parser.add_argument("--version", action="version", version=f"DEDSEC v{__version__}")

    args = parser.parse_args()

    url = args.url
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    domain = get_domain(url)
    if not domain:
        error("Could not extract domain from URL.")
        sys.exit(1)

    if args.market:
        selected = MARKET_PROFILE_MODULES
    else:
        selected = list(MODULE_MAP.keys()) if "all" in args.modules else args.modules

    print(f"  Target URL : {url}")
    print(f"  Domain     : {domain}")
    print(f"  Modules    : {', '.join(selected)}")
    print(f"  Timeout    : {args.timeout}s")
    num_threads = min(args.threads, len(selected))
    print(f"  Threads    : {num_threads} parallel module(s)")

    capture = _PerThreadCapture(sys.stdout)
    sys.stdout = capture

    results = {}
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        ordered_futures = [
            (key, executor.submit(_run_module, key, url, domain, args.timeout, capture))
            for key in selected
        ]
        for key, future in ordered_futures:
            try:
                _, result, output = future.result()  # first element is key (already in scope)
            except Exception as exc:
                result = {"error": str(exc)}
                output = f"{Colors.RED}[-]{Colors.RESET} Module '{key}' failed: {exc}\n"
            results[key] = result
            capture._real.write(output)

    sys.stdout = capture._real

    generate_report(url, domain, results, json_output=args.json, output_file=args.output)


if __name__ == "__main__":
    main()
