import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section, shannon_entropy, warn

JS_SRC_RE = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
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
URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

NEXT_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key": re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'),
    "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "GitHub Token": re.compile(r'gh[pousr]_[A-Za-z0-9]{36,255}'),
    "Stripe Secret": re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
    "Stripe Publishable": re.compile(r'pk_live_[0-9a-zA-Z]{24}'),
    "Slack Token": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'),
    "Slack Webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    "SendGrid API": re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),
    "Mailgun API": re.compile(r'key-[0-9a-zA-Z]{32}'),
    "Twilio SID": re.compile(r'AC[0-9a-fA-F]{32}'),
    "Firebase URL": re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    "JWT Token": re.compile(r'eyJ[a-zA-Z0-9\-_=]{10,}\.[a-zA-Z0-9\-_=]{10,}\.?[a-zA-Z0-9\-_.+/=]*'),
    "Private Key": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "Internal IPv4": re.compile(
        r'(?<![.\d])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![.\d])'
    ),
    "Hardcoded Password": re.compile(
        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'
    ),
    "Generic API Token": re.compile(
        r'(?i)(?:api_key|apikey|api-key|token|secret|auth_token|access_token)'
        r'\s*[=:]\s*["\'][a-zA-Z0-9\-_\.]{16,}["\']'
    ),
}

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/__graphql", "/gql", "/query", "/api/query"]
_FP_EMAIL_SUFFIXES = (".png", ".jpg", ".gif", ".css", ".js", ".svg", ".ico", ".woff")


def _same_scope_asset(asset_url, domain):
    host = (urlparse(asset_url).hostname or "").lower()
    return host == domain or host.endswith("." + domain)


def _scan_basic_auth_urls(content, source_label):
    findings = []
    for raw_url in URL_RE.findall(content):
        candidate = raw_url.rstrip("),.;")
        try:
            parsed = urlparse(candidate)
        except Exception:
            continue
        # Structural validation avoids interpreting query syntax such as
        # Google Fonts "family=Inter:wght@300" as user:password@host.
        if parsed.username is None or parsed.password is None or not parsed.hostname:
            continue
        findings.append(
            {
                "type": "Basic Auth URL",
                "snippet": candidate[:80],
                "source": source_label,
                "entropy": shannon_entropy(candidate[:80]),
                "confidence": "high",
                "validated": True,
            }
        )
    return findings


def _scan_for_secrets(content, source_label):
    """Scan source for strongly typed secret shapes with conservative filtering."""
    findings = _scan_basic_auth_urls(content, source_label)
    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            snippet = match.group(0)[:80]
            entropy = shannon_entropy(snippet)
            if label in ("Generic API Token", "Hardcoded Password") and entropy < 4.0:
                continue
            confidence = "high" if label not in {"Internal IPv4", "Firebase URL"} else "medium"
            findings.append(
                {
                    "type": label,
                    "snippet": snippet,
                    "source": source_label,
                    "entropy": entropy,
                    "confidence": confidence,
                    "validated": confidence == "high",
                }
            )
    return findings


def _extract_next_data(html):
    endpoints = set()
    match = NEXT_DATA_RE.search(html)
    if not match:
        return endpoints
    try:
        import json

        data = json.loads(match.group(1))

        def _walk(obj, depth=0):
            if depth > 10:
                return
            if isinstance(obj, str):
                if obj.startswith("/") and len(obj) > 2 and " " not in obj:
                    endpoints.add(obj)
            elif isinstance(obj, dict):
                for value in obj.values():
                    _walk(value, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, depth + 1)

        _walk(data)
    except Exception:
        pass
    return endpoints


def _classify_route(value):
    path = value.strip()
    if not path.startswith("/"):
        path = "/" + path
    lower = path.lower()
    first = lower.lstrip("/").split("/", 1)[0]
    api_like = (
        lower.startswith("/api/")
        or lower in {"/api", "/graphql", "/gql"}
        or bool(re.match(r"^/v\d+(?:/|$)", lower))
        or first in {"rest", "webhook"}
    )
    return {
        "path": path,
        "kind": "api_candidate" if api_like else "navigation_route",
        "confidence": "medium",
    }


def run(url, domain, timeout=10):
    section("JS & Endpoint Extraction", "📜")
    results = {
        "js_files": [],
        "endpoints": [],
        "routes": [],
        "emails": [],
        "secrets": [],
        "graphql_paths": [],
        "external_js_skipped": [],
    }

    resp = safe_request(url, timeout=timeout)
    if resp is None:
        error("Could not connect to target.")
        results["error"] = "Could not connect to target"
        return results

    body = resp.text
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    raw_js = JS_SRC_RE.findall(body)
    js_files = []
    external_js = []
    seen_js = set()
    for src in raw_js:
        if src.startswith("//"):
            src = f"{urlparse(url).scheme}:{src}"
        elif src.startswith("/"):
            src = urljoin(base_url, src)
        elif not src.startswith("http"):
            src = urljoin(url, src)
        if src in seen_js:
            continue
        seen_js.add(src)
        if _same_scope_asset(src, domain):
            js_files.append(src)
        else:
            external_js.append(src)

    if js_files:
        info("In-scope JS Files Found", str(len(js_files)))
        for js in js_files[:20]:
            print(f"       {Colors.CYAN}• {js}{Colors.RESET}")
    else:
        warn("No in-scope JavaScript files found.")
    if external_js:
        print(f"  {Colors.DIM}[ ] Skipped {len(external_js)} external JS asset(s){Colors.RESET}")

    all_endpoints = set(ENDPOINT_RE.findall(body))
    all_endpoints.update(_extract_next_data(body))
    all_secrets = _scan_for_secrets(body, "page-html")

    def _fetch_js(js_url):
        js_resp = safe_request(js_url, timeout=timeout)
        if js_resp is not None and js_resp.status_code == 200:
            return js_url, js_resp.text
        return js_url, None

    with ThreadPoolExecutor(max_workers=min(10, max(1, len(js_files)))) as executor:
        futures = {executor.submit(_fetch_js, js_url): js_url for js_url in js_files}
        for future in as_completed(futures):
            js_url, js_content = future.result()
            if js_content:
                all_endpoints.update(ENDPOINT_RE.findall(js_content))
                all_secrets.extend(_scan_for_secrets(js_content, js_url))

    seen_secrets = set()
    deduped_secrets = []
    for item in all_secrets:
        key = (item["type"], item["snippet"][:40], item["source"])
        if key not in seen_secrets:
            seen_secrets.add(key)
            deduped_secrets.append(item)
    all_secrets = deduped_secrets

    routes = []
    seen_routes = set()
    for endpoint in sorted(all_endpoints):
        if len(endpoint) <= 3:
            continue
        route = _classify_route(endpoint)
        if route["path"] in seen_routes:
            continue
        seen_routes.add(route["path"])
        routes.append(route)
        if len(routes) >= 100:
            break

    api_candidates = [item for item in routes if item["kind"] == "api_candidate"]
    navigation = [item for item in routes if item["kind"] == "navigation_route"]
    if api_candidates:
        info("API Candidates Found", str(len(api_candidates)))
        for item in api_candidates[:30]:
            print(f"       {Colors.GREEN}• {item['path']}{Colors.RESET}")
    if navigation:
        info("Navigation Routes Found", str(len(navigation)))
        for item in navigation[:30]:
            print(f"       {Colors.CYAN}• {item['path']}{Colors.RESET}")
    if not routes:
        warn("No route candidates found.")

    found_graphql = []
    for gql_path in GRAPHQL_PATHS:
        gql_url = urljoin(base_url, gql_path)
        gql_resp = safe_request(gql_url, timeout=timeout, allow_redirects=False)
        if gql_resp is None or gql_resp.status_code in (404, 410):
            continue
        content_type = gql_resp.headers.get("Content-Type", "").lower()
        body_lower = gql_resp.text[:1000].lower()
        signature = (
            "graphql" in body_lower
            or "application/graphql" in content_type
            or (gql_resp.status_code in {400, 405} and "query" in body_lower)
        )
        found_graphql.append(
            {
                "path": gql_path,
                "status": gql_resp.status_code,
                "signature_match": signature,
                "classification": "candidate" if signature else "unverified-response",
            }
        )
        if signature:
            info("GraphQL Candidate", f"{gql_path} ({gql_resp.status_code})")
    results["graphql_paths"] = found_graphql

    if all_secrets:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} {Colors.BOLD}Potential Secret-Shaped Values:{Colors.RESET}")
        for item in all_secrets[:30]:
            src_short = item["source"] if len(item["source"]) < 60 else "..." + item["source"][-57:]
            print(f"  {Colors.YELLOW}⚠{Colors.RESET}  {Colors.BOLD}{item['type']}{Colors.RESET}")
            print(f"       {Colors.DIM}Snippet: {item['snippet']}{Colors.RESET}")
            print(f"       {Colors.DIM}In: {src_short}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✔{Colors.RESET}  No supported secret patterns detected in in-scope source.")

    emails = sorted(set(EMAIL_RE.findall(body)))
    emails = [e for e in emails if not any(e.endswith(x) for x in _FP_EMAIL_SUFFIXES)][:30]
    if emails:
        info("Emails Found", str(len(emails)))
        for email in emails:
            print(f"       {Colors.YELLOW}• {email}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[ ] No email addresses found{Colors.RESET}")

    results["js_files"] = js_files
    results["external_js_skipped"] = external_js
    results["routes"] = routes
    results["endpoints"] = [item["path"] for item in api_candidates]
    results["emails"] = emails
    results["secrets"] = all_secrets
    return results
