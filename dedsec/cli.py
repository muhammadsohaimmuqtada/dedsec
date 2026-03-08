import argparse
import importlib
import sys
from dedsec.core.banner import print_banner
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

    results = {}
    for key in selected:
        module_path, label = MODULE_MAP[key]
        try:
            mod = importlib.import_module(module_path)
            result = mod.run(url, domain, timeout=args.timeout)
            results[key] = result
        except Exception as e:
            error(f"Module '{key}' failed: {e}")
            results[key] = {"error": str(e)}

    generate_report(url, domain, results, json_output=args.json, output_file=args.output)


if __name__ == "__main__":
    main()
