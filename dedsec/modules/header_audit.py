from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section, warn

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "severity": "HIGH",
        "description": "Forces HTTPS and helps prevent protocol downgrade attacks.",
        "validator": lambda value, url: ("max-age=" in value.lower(), "Missing max-age directive."),
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "severity": "HIGH",
        "description": "Restricts script and resource origins to reduce XSS risk.",
        "validator": lambda value, url: (len(value.strip()) > 0, "Empty CSP value."),
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Helps prevent clickjacking by restricting framing.",
        "validator": lambda value, url: (value.lower() in {"deny", "sameorigin"}, "Expected DENY or SAMEORIGIN."),
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Prevents MIME sniffing in browsers.",
        "validator": lambda value, url: (value.lower() == "nosniff", "Expected nosniff."),
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Deprecated in modern browsers; if present, '0' is the safest modern setting.",
        "validator": lambda value, url: (value.strip() == "0", "Deprecated header should normally be set to '0' or omitted."),
        "optional": True,
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity": "LOW",
        "description": "Controls how much referrer information is leaked cross-origin.",
        "validator": lambda value, url: (value.lower() in {
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin",
        }, "Prefer a privacy-preserving policy such as strict-origin-when-cross-origin."),
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity": "LOW",
        "description": "Restricts access to browser features such as camera and microphone.",
        "validator": lambda value, url: (len(value.strip()) > 0, "Empty Permissions-Policy value."),
    },
    "cross-origin-opener-policy": {
        "label": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "MEDIUM",
        "description": "Separates browsing contexts to reduce cross-origin attacks.",
        "validator": lambda value, url: (value.lower() in {"same-origin", "same-origin-allow-popups"}, "Prefer same-origin or same-origin-allow-popups."),
    },
    "cross-origin-resource-policy": {
        "label": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "MEDIUM",
        "description": "Restricts which origins may load site resources.",
        "validator": lambda value, url: (value.lower() in {"same-origin", "same-site", "cross-origin"}, "Unexpected CORP value."),
    },
    "cross-origin-embedder-policy": {
        "label": "Cross-Origin-Embedder-Policy (COEP)",
        "severity": "MEDIUM",
        "description": "Requires embedded resources to opt into cross-origin use.",
        "validator": lambda value, url: (value.lower() in {"require-corp", "credentialless"}, "Expected require-corp or credentialless."),
    },
    "x-permitted-cross-domain-policies": {
        "label": "X-Permitted-Cross-Domain-Policies",
        "severity": "LOW",
        "description": "Restricts Adobe Flash and PDF cross-domain policy handling.",
        "validator": lambda value, url: (value.lower() in {"none", "master-only"}, "Prefer none or master-only."),
    },
    "cache-control": {
        "label": "Cache-Control",
        "severity": "LOW",
        "description": "Sensitive authenticated content should generally disable caching.",
        "validator": lambda value, url: (any(token in value.lower() for token in ("no-store", "private", "no-cache")), "Consider no-store/private for sensitive responses."),
        "optional": True,
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
SEVERITY_COLORS = {"HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "LOW": Colors.DIM}


def _validate_header(meta, value, url):
    validator = meta.get("validator")
    if not validator:
        return True, None
    return validator(value, url)


def run(url, domain, timeout=10):
    section("HTTP Header Audit", "📋")
    results = {"present": {}, "missing": {}, "weak": {}, "disclosure": {}}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    headers_lower = {key.lower(): value for key, value in resp.headers.items()}

    print(f"\n{Colors.BOLD}  Security Headers:{Colors.RESET}")
    present = {}
    missing = {}
    weak = {}

    for header_key, meta in SECURITY_HEADERS.items():
        severity = meta["severity"]
        color = SEVERITY_COLORS.get(severity, Colors.DIM)
        optional = meta.get("optional", False)

        if header_key not in headers_lower:
            if optional:
                print(f"  {Colors.DIM}[ ]{Colors.RESET}  {meta['label']} not present")
                continue
            print(f"  {Colors.RED}✘{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET} [{color}{severity}{Colors.RESET}]")
            print(f"      {Colors.DIM}{meta['description']}{Colors.RESET}")
            missing[header_key] = {"severity": severity, "description": meta["description"]}
            continue

        value = headers_lower[header_key]
        is_valid, detail = _validate_header(meta, value, url)
        if is_valid:
            print(f"  {Colors.GREEN}✔{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET}")
            print(f"      {Colors.DIM}Value: {value[:100]}{'...' if len(value) > 100 else ''}{Colors.RESET}")
            present[header_key] = value
            continue

        print(f"  {Colors.YELLOW}!{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET} [{color}{severity}{Colors.RESET}]")
        print(f"      {Colors.DIM}Weak value: {value[:100]}{'...' if len(value) > 100 else ''}{Colors.RESET}")
        print(f"      {Colors.DIM}{detail}{Colors.RESET}")
        weak[header_key] = {"severity": severity, "value": value, "issue": detail}

    results["present"] = present
    results["missing"] = missing
    results["weak"] = weak

    print(f"\n{Colors.BOLD}  Information Disclosure:{Colors.RESET}")
    for header in DISCLOSURE_HEADERS:
        if header in headers_lower:
            value = headers_lower[header]
            warn(f"'{header}': {value}  <- leaks implementation details")
            results["disclosure"][header] = value
        else:
            print(f"  {Colors.GREEN}✔{Colors.RESET}  '{header}' not present")

    effective_score = len(present)
    penalty = len(weak)
    total = len([key for key, meta in SECURITY_HEADERS.items() if not meta.get("optional", False)])
    pct = int(max(effective_score - penalty, 0) / total * 100) if total else 0
    color = Colors.GREEN if pct >= 70 else Colors.YELLOW if pct >= 40 else Colors.RED
    info("Security Score", f"{color}{pct}%{Colors.RESET} ({len(present)} strong, {len(weak)} weak, {len(missing)} missing)")
    results["score"] = {
        "percentage": pct,
        "strong": len(present),
        "weak": len(weak),
        "missing": len(missing),
    }

    return results
