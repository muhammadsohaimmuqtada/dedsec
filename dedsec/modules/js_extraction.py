import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error, shannon_entropy

JS_SRC_RE   = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
ENDPOINT_RE = re.compile(
    r'["`](/?(?:api|v\d+|rest|graphql|admin|auth|login|user|account|dashboard'
    r'|internal|private|webhook|callback|upload|download|export|import|report'
    r'|search|config|settings|profile|session|token|refresh|verify|activate'
    r'|reset|password|oauth|connect|subscribe|unsubscribe|manage|invite'
    r'|billing|payment|checkout|order|product|catalog|inventory)'
    r'[/\w\-\.%?=&#@:]*)["`]',
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

NEXT_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

# Regex patterns to detect secrets/credentials in source and JS files
SECRET_PATTERNS = {
    "AWS Access Key":     re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key":     re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'),
    "Google API Key":     re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "GitHub Token":       re.compile(r'gh[pousr]_[A-Za-z0-9]{36,255}'),
    "Stripe Secret":      re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
    "Stripe Publishable": re.compile(r'pk_live_[0-9a-zA-Z]{24}'),
    "Slack Token":        re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Slack Webhook":      re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    "SendGrid API":       re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),
    "Mailgun API":        re.compile(r'key-[0-9a-zA-Z]{32}'),
    "Twilio SID":         re.compile(r'AC[0-9a-fA-F]{32}'),
    "Firebase URL":       re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    "Firebase API Key":   re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "JWT Token":          re.compile(r'eyJ[a-zA-Z0-9\-_=]{10,}\.[a-zA-Z0-9\-_=]{10,}\.?[a-zA-Z0-9\-_.+/=]*'),
    "Private Key":        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "Basic Auth URL":     re.compile(r'https?://[^:@\s"\']{3,}:[^:@\s"\']{3,}@[^/\s"\']+'),
    "Internal IPv4":      re.compile(
        r'(?<![.\d])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![.\d])'
    ),
    "Hardcoded Password": re.compile(
        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'
    ),
    "Generic API Token":  re.compile(
        r'(?i)(?:api_key|apikey|api-key|token|secret|auth_token|access_token)'
        r'\s*[=:]\s*["\'][a-zA-Z0-9\-_\.]{16,}["\']'
    ),
}

# Known GraphQL paths to probe
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/__graphql", "/gql", "/query", "/api/query"]

# False-positive email domain suffixes to filter out
_FP_EMAIL_SUFFIXES = (".png", ".jpg", ".gif", ".css", ".js", ".svg", ".ico", ".woff")


def _scan_for_secrets(content, source_label):
    """Scan a string for known secret patterns and filter generic matches by Shannon Entropy."""
    findings = []
    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            snippet = match.group(0)[:80]
            
            # For generic API tokens/passwords, apply Shannon Entropy threshold (> 4.0)
            if label in ("Generic API Token", "Hardcoded Password"):
                val_entropy = shannon_entropy(snippet)
                if val_entropy < 4.0:
                    continue # Ignore low-entropy matches like "password=password123" or variable names
            
            findings.append({
                "type": label,
                "snippet": snippet,
                "source": source_label,
                "entropy": shannon_entropy(snippet)
            })
    return findings


def _extract_next_data(html):
    """Extract API paths and config from Next.js __NEXT_DATA__ blob."""
    endpoints = set()
    match = NEXT_DATA_RE.search(html)
    if not match:
        return endpoints
    try:
        import json
        data = json.loads(match.group(1))
        # Flatten all string values and pick up anything that looks like a path
        def _walk(obj, depth=0):
            if depth > 10:
                return
            if isinstance(obj, str):
                if obj.startswith("/") and len(obj) > 2 and " " not in obj:
                    endpoints.add(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, depth + 1)
        _walk(data)
    except Exception:
        pass
    return endpoints


def run(url, domain, timeout=10):
    section("JS & Endpoint Extraction", "📜")
    results = {"js_files": [], "endpoints": [], "emails": [], "secrets": [], "graphql_paths": []}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        results["error"] = "Could not connect to target"
        return results

    body = resp.text
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # --- Extract JS file URLs ---
    raw_js = JS_SRC_RE.findall(body)
    js_files = []
    seen_js = set()
    for src in raw_js:
        if src.startswith("//"):
            src = f"https:{src}"
        elif src.startswith("/"):
            src = urljoin(base_url, src)
        elif not src.startswith("http"):
            src = urljoin(url, src)
        if src not in seen_js:
            seen_js.add(src)
            js_files.append(src)

    if js_files:
        info("JS Files Found", str(len(js_files)))
        for js in js_files[:20]:
            print(f"       {Colors.CYAN}\u2022 {js}{Colors.RESET}")
        if len(js_files) > 20:
            print(f"       {Colors.DIM}... and {len(js_files) - 20} more{Colors.RESET}")
    else:
        warn("No JavaScript files found.")

    # --- Extract endpoints from page source ---
    all_endpoints = set(ENDPOINT_RE.findall(body))

    # --- Extract Next.js __NEXT_DATA__ ---
    next_endpoints = _extract_next_data(body)
    if next_endpoints:
        info("Next.js __NEXT_DATA__ paths found", str(len(next_endpoints)))
        all_endpoints.update(next_endpoints)

    # --- Scan page source for secrets ---
    all_secrets = _scan_for_secrets(body, "page-html")

    # --- Fetch and scan JS files concurrently ---
    def _fetch_js(js_url):
        js_resp = safe_request(js_url, timeout=timeout)
        if js_resp and js_resp.status_code == 200:
            return js_url, js_resp.text
        return js_url, None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_fetch_js, js_url): js_url for js_url in js_files}
        for future in as_completed(futures):
            js_url, js_content = future.result()
            if js_content:
                more_endpoints = ENDPOINT_RE.findall(js_content)
                all_endpoints.update(more_endpoints)
                js_secrets = _scan_for_secrets(js_content, js_url)
                all_secrets.extend(js_secrets)

    # Deduplicate secrets by (type, snippet)
    seen_secrets = set()
    deduped_secrets = []
    for s in all_secrets:
        key = (s["type"], s["snippet"][:40])
        if key not in seen_secrets:
            seen_secrets.add(key)
            deduped_secrets.append(s)
    all_secrets = deduped_secrets

    # Filter and display endpoints
    endpoints = sorted(e for e in all_endpoints if len(e) > 3)[:100]
    if endpoints:
        info("API Endpoints Found", str(len(endpoints)))
        for ep in endpoints[:30]:
            print(f"       {Colors.GREEN}\u2022 {ep}{Colors.RESET}")
        if len(endpoints) > 30:
            print(f"       {Colors.DIM}... and {len(endpoints) - 30} more{Colors.RESET}")
    else:
        warn("No API endpoints found.")

    # --- Probe GraphQL paths ---
    found_graphql = []
    for gql_path in GRAPHQL_PATHS:
        gql_url = urljoin(base_url, gql_path)
        gql_resp = safe_request(gql_url, timeout=timeout)
        if gql_resp and gql_resp.status_code not in (404, 410):
            found_graphql.append({"path": gql_path, "status": gql_resp.status_code})
            info("GraphQL Endpoint", f"{gql_path} ({gql_resp.status_code})")
    results["graphql_paths"] = found_graphql

    # --- Secrets report ---
    if all_secrets:
        print(f"\n{Colors.RED}[!]{Colors.RESET} {Colors.BOLD}Potential Secrets Found:{Colors.RESET}")
        for s in all_secrets[:30]:
            src_short = s["source"] if len(s["source"]) < 60 else "..." + s["source"][-57:]
            print(f"  {Colors.RED}\u26a0{Colors.RESET}  {Colors.BOLD}{s['type']}{Colors.RESET}")
            print(f"       {Colors.DIM}Snippet: {s['snippet']}{Colors.RESET}")
            print(f"       {Colors.DIM}In: {src_short}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}\u2714{Colors.RESET}  No obvious secrets detected in page or JS files.")

    # --- Emails ---
    emails = sorted(set(EMAIL_RE.findall(body)))
    emails = [e for e in emails if not any(e.endswith(x) for x in _FP_EMAIL_SUFFIXES)][:30]
    if emails:
        info("Emails Found", str(len(emails)))
        for em in emails:
            print(f"       {Colors.YELLOW}\u2022 {em}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[ ] No email addresses found{Colors.RESET}")

    results["js_files"] = js_files
    results["endpoints"] = endpoints
    results["emails"] = emails
    results["secrets"] = all_secrets
    return results
