import re
from urllib.parse import urljoin, urlparse
from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors

JS_SRC_RE    = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
ENDPOINT_RE  = re.compile(r'["\`](\/?(?:api|v\d+|rest|graphql|admin|auth|login|user|account|dashboard)[/\w\-\.%?=&#+:@]*)["\`]', re.IGNORECASE)
EMAIL_RE     = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


def run(url, domain, timeout=10):
    section("JS & Endpoint Extraction", "📜")
    results = {"js_files": [], "endpoints": [], "emails": []}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    body = resp.text

    # Extract JS file URLs
    raw_js = JS_SRC_RE.findall(body)
    js_files = []
    seen_js = set()
    for src in raw_js:
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = urljoin(url, src)
        elif not src.startswith("http"):
            src = urljoin(url, src)
        # Only include JS from the same or external domains
        if src not in seen_js:
            seen_js.add(src)
            js_files.append(src)

    if js_files:
        info("JS Files Found", str(len(js_files)))
        for js in js_files[:20]:
            print(f"       {Colors.CYAN}• {js}{Colors.RESET}")
        if len(js_files) > 20:
            print(f"       {Colors.DIM}... and {len(js_files)-20} more{Colors.RESET}")
    else:
        warn("No JavaScript files found.")

    # Extract endpoints from page source
    raw_endpoints = ENDPOINT_RE.findall(body)
    endpoints = sorted(set(raw_endpoints))

    # Also probe first 3 JS files for more endpoints
    for js_url in js_files[:3]:
        js_resp = safe_request(js_url, timeout=timeout)
        if js_resp and js_resp.status_code == 200:
            more = ENDPOINT_RE.findall(js_resp.text)
            endpoints = sorted(set(endpoints + more))

    endpoints = [e for e in endpoints if len(e) > 3][:50]

    if endpoints:
        info("API Endpoints Found", str(len(endpoints)))
        for ep in endpoints[:30]:
            print(f"       {Colors.GREEN}• {ep}{Colors.RESET}")
        if len(endpoints) > 30:
            print(f"       {Colors.DIM}... and {len(endpoints)-30} more{Colors.RESET}")
    else:
        warn("No API endpoints found.")

    # Extract email addresses
    emails = sorted(set(EMAIL_RE.findall(body)))
    # Filter common false positives
    emails = [e for e in emails if not any(e.endswith(x) for x in [".png", ".jpg", ".gif", ".css", ".js"])]
    emails = emails[:30]

    if emails:
        info("Emails Found", str(len(emails)))
        for em in emails:
            print(f"       {Colors.YELLOW}• {em}{Colors.RESET}")
    else:
        print(f"{Colors.DIM}[ ] No email addresses found{Colors.RESET}")

    results["js_files"]  = js_files
    results["endpoints"] = endpoints
    results["emails"]    = emails
    return results
