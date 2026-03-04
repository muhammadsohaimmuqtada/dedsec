from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "severity": "HIGH",
        "description": "Forces HTTPS, prevents protocol downgrade attacks.",
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "severity": "HIGH",
        "description": "Mitigates XSS by restricting resource origins.",
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by disallowing framing.",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing.",
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Deprecated XSS filter for old browsers; can introduce vulnerabilities in modern ones. Omit or set to '0'.",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls referrer information sent in requests.",
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity": "LOW",
        "description": "Controls browser feature access (camera, mic, etc.).",
    },
    "cross-origin-opener-policy": {
        "label": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "MEDIUM",
        "description": "Isolates browsing context from cross-origin documents.",
    },
    "cross-origin-resource-policy": {
        "label": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "MEDIUM",
        "description": "Prevents cross-origin resource loading.",
    },
    "cross-origin-embedder-policy": {
        "label": "Cross-Origin-Embedder-Policy (COEP)",
        "severity": "MEDIUM",
        "description": "Requires cross-origin resources to opt-in to embedding.",
    },
    "x-permitted-cross-domain-policies": {
        "label": "X-Permitted-Cross-Domain-Policies",
        "severity": "LOW",
        "description": "Restricts Adobe Flash/PDF cross-domain requests.",
    },
    "cache-control": {
        "label": "Cache-Control",
        "severity": "LOW",
        "description": "Controls caching behavior for sensitive responses.",
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]

SEVERITY_COLORS = {
    "HIGH":   Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW":    Colors.DIM,
}


def run(url, domain, timeout=10):
    section("HTTP Header Audit", "📋")
    results = {"present": {}, "missing": {}, "disclosure": {}}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    print(f"\n{Colors.BOLD}  Security Headers:{Colors.RESET}")
    present = {}
    missing = {}

    for hdr_key, meta in SECURITY_HEADERS.items():
        if hdr_key in headers_lower:
            val = headers_lower[hdr_key]
            print(f"  {Colors.GREEN}✔{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET}")
            print(f"      {Colors.DIM}Value: {val[:80]}{'...' if len(val) > 80 else ''}{Colors.RESET}")
            present[hdr_key] = val
        else:
            sev = meta["severity"]
            col = SEVERITY_COLORS.get(sev, Colors.DIM)
            print(f"  {Colors.RED}✘{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET} "
                  f"[{col}{sev}{Colors.RESET}]")
            print(f"      {Colors.DIM}{meta['description']}{Colors.RESET}")
            missing[hdr_key] = {"severity": sev, "description": meta["description"]}

    results["present"] = present
    results["missing"] = missing

    # Information disclosure check
    print(f"\n{Colors.BOLD}  Information Disclosure:{Colors.RESET}")
    for hdr in DISCLOSURE_HEADERS:
        if hdr in headers_lower:
            val = headers_lower[hdr]
            warn(f"'{hdr}': {val}  ← leaks server technology")
            results["disclosure"][hdr] = val
        else:
            print(f"  {Colors.GREEN}✔{Colors.RESET}  '{hdr}' not present")

    score = len(present)
    total = len(SECURITY_HEADERS)
    pct = int(score / total * 100)
    color = Colors.GREEN if pct >= 70 else Colors.YELLOW if pct >= 40 else Colors.RED
    info("Security Score", f"{color}{score}/{total} headers present ({pct}%){Colors.RESET}")
    results["score"] = f"{score}/{total} ({pct}%)"

    return results
