from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section, warn


def _analyze_csp(value):
    issues = []
    val_lower = value.lower()
    if "'unsafe-inline'" in val_lower:
        issues.append("script/style policy includes 'unsafe-inline'")
    if "'unsafe-eval'" in val_lower:
        issues.append("policy includes 'unsafe-eval'")

    directives = [item.strip() for item in val_lower.split(";") if item.strip()]
    default_src_found = False
    script_src_found = False
    for directive in directives:
        parts = directive.split()
        if not parts:
            continue
        name, sources = parts[0], parts[1:]
        if name == "default-src":
            default_src_found = True
            if "*" in sources:
                issues.append("default-src allows wildcard '*'")
        elif name == "script-src":
            script_src_found = True
            if "*" in sources:
                issues.append("script-src allows wildcard '*'")
            if "data:" in sources:
                issues.append("script-src allows data: URIs")
    if not default_src_found and not script_src_found:
        issues.append("no default-src or script-src directive")
    return (not issues, "; ".join(issues) if issues else None)


def _validate_hsts(value, url):
    lower = value.lower()
    if "max-age=" not in lower:
        return False, "Missing max-age directive."
    try:
        max_age = int(lower.split("max-age=", 1)[1].split(";", 1)[0].strip())
    except (ValueError, IndexError):
        return False, "Invalid max-age directive."
    if max_age < 31536000:
        return False, "max-age is below the commonly recommended one-year baseline."
    return True, None


SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "severity": "MEDIUM",
        "group": "core",
        "weight": 3,
        "description": "Enforces HTTPS after the browser has learned the policy.",
        "validator": _validate_hsts,
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "severity": "MEDIUM",
        "group": "core",
        "weight": 3,
        "description": "Mitigates classes of content-injection attacks when well configured.",
        "validator": lambda value, url: _analyze_csp(value),
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "severity": "MEDIUM",
        "group": "core",
        "weight": 2,
        "description": "Restricts framing when CSP frame-ancestors is not used.",
        "validator": lambda value, url: (
            value.lower() in {"deny", "sameorigin"},
            "Expected DENY or SAMEORIGIN.",
        ),
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "LOW",
        "group": "core",
        "weight": 2,
        "description": "Prevents MIME sniffing in browsers.",
        "validator": lambda value, url: (value.lower() == "nosniff", "Expected nosniff."),
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "severity": "LOW",
        "group": "privacy",
        "weight": 1,
        "description": "Controls referrer information sent cross-origin.",
        "validator": lambda value, url: (
            value.lower()
            in {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"},
            "Prefer a privacy-preserving policy such as strict-origin-when-cross-origin.",
        ),
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "severity": "INFO",
        "group": "optional-hardening",
        "optional": True,
        "description": "Restricts access to selected browser capabilities.",
        "validator": lambda value, url: (bool(value.strip()), "Empty Permissions-Policy value."),
    },
    "cross-origin-opener-policy": {
        "label": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "INFO",
        "group": "cross-origin-isolation",
        "optional": True,
        "description": "Optional browsing-context isolation control.",
        "validator": lambda value, url: (
            value.lower() in {"same-origin", "same-origin-allow-popups", "unsafe-none"},
            "Unexpected COOP value.",
        ),
    },
    "cross-origin-resource-policy": {
        "label": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "INFO",
        "group": "cross-origin-isolation",
        "optional": True,
        "description": "Optional resource-loading policy used by some isolation designs.",
        "validator": lambda value, url: (
            value.lower() in {"same-origin", "same-site", "cross-origin"},
            "Unexpected CORP value.",
        ),
    },
    "cross-origin-embedder-policy": {
        "label": "Cross-Origin-Embedder-Policy (COEP)",
        "severity": "INFO",
        "group": "cross-origin-isolation",
        "optional": True,
        "description": "Optional control required by some cross-origin isolation use cases.",
        "validator": lambda value, url: (
            value.lower() in {"require-corp", "credentialless", "unsafe-none"},
            "Unexpected COEP value.",
        ),
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "severity": "INFO",
        "group": "legacy",
        "optional": True,
        "description": "Deprecated legacy XSS filter control.",
        "validator": lambda value, url: (
            value.strip() == "0",
            "Deprecated header should normally be set to '0' or omitted.",
        ),
    },
    "x-permitted-cross-domain-policies": {
        "label": "X-Permitted-Cross-Domain-Policies",
        "severity": "INFO",
        "group": "legacy",
        "optional": True,
        "description": "Legacy Adobe cross-domain policy control.",
        "validator": lambda value, url: (
            value.lower() in {"none", "master-only"},
            "Prefer none or master-only when this legacy control is relevant.",
        ),
    },
    "cache-control": {
        "label": "Cache-Control",
        "severity": "INFO",
        "group": "context-dependent",
        "optional": True,
        "description": "Caching requirements depend on whether the response contains sensitive data.",
        "validator": lambda value, url: (True, None),
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
INFORMATIONAL_HEADERS = ["nel", "report-to"]
SEVERITY_COLORS = {"HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "LOW": Colors.DIM, "INFO": Colors.DIM}


def _validate_header(meta, value, url):
    validator = meta.get("validator")
    return validator(value, url) if validator else (True, None)


def run(url, domain, timeout=10):
    section("HTTP Header Audit", "📋")
    results = {
        "present": {},
        "missing": {},
        "weak": {},
        "optional_missing": {},
        "disclosure": {},
        "informational": {},
        "posture": {},
    }

    resp = safe_request(url, timeout=timeout)
    if resp is None:
        error("Could not connect to target.")
        results["error"] = "Could not connect to target"
        return results

    headers_lower = {key.lower(): value for key, value in resp.headers.items()}
    print(f"\n{Colors.BOLD}  Security Headers:{Colors.RESET}")

    present = {}
    missing = {}
    weak = {}
    optional_missing = {}
    total_weight = 0
    earned_weight = 0

    for header_key, meta in SECURITY_HEADERS.items():
        severity = meta["severity"]
        color = SEVERITY_COLORS.get(severity, Colors.DIM)
        optional = meta.get("optional", False)
        weight = int(meta.get("weight", 0))
        if not optional:
            total_weight += weight

        if header_key not in headers_lower:
            target = optional_missing if optional else missing
            target[header_key] = {
                "severity": severity,
                "description": meta["description"],
                "group": meta["group"],
            }
            marker = Colors.DIM if optional else Colors.YELLOW
            label = "not configured" if optional else "missing"
            print(f"  {marker}[ ]{Colors.RESET} {meta['label']}: {label}")
            continue

        value = headers_lower[header_key]
        is_valid, detail = _validate_header(meta, value, url)
        if is_valid:
            present[header_key] = value
            if not optional:
                earned_weight += weight
            print(f"  {Colors.GREEN}✔{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET}")
            print(f"      {Colors.DIM}Value: {value[:100]}{'...' if len(value) > 100 else ''}{Colors.RESET}")
        else:
            weak[header_key] = {
                "severity": severity,
                "value": value,
                "issue": detail,
                "group": meta["group"],
            }
            print(f"  {Colors.YELLOW}!{Colors.RESET}  {Colors.BOLD}{meta['label']}{Colors.RESET} [{color}{severity}{Colors.RESET}]")
            print(f"      {Colors.DIM}{detail}{Colors.RESET}")

    results["present"] = present
    results["missing"] = missing
    results["weak"] = weak
    results["optional_missing"] = optional_missing

    print(f"\n{Colors.BOLD}  Information Disclosure Observations:{Colors.RESET}")
    for header in DISCLOSURE_HEADERS:
        if header in headers_lower:
            value = headers_lower[header]
            print(f"  {Colors.DIM}[i] '{header}': {value}{Colors.RESET}")
            results["disclosure"][header] = value

    print(f"\n{Colors.BOLD}  Informational Headers:{Colors.RESET}")
    for header in INFORMATIONAL_HEADERS:
        if header in headers_lower:
            results["informational"][header] = headers_lower[header]
            info(f"'{header}' present", headers_lower[header][:100])
        else:
            print(f"  {Colors.DIM}[ ] '{header}' not present{Colors.RESET}")

    percentage = int(round((earned_weight / total_weight) * 100)) if total_weight else 100
    core_missing = [key for key, value in missing.items() if value.get("group") == "core"]
    core_weak = [key for key, value in weak.items() if value.get("group") == "core"]
    results["posture"] = {
        "weighted_coverage_percent": percentage,
        "core_missing": core_missing,
        "core_weak": core_weak,
        "optional_hardening_missing": sorted(optional_missing),
        "note": "Coverage score measures selected header controls; it is not a vulnerability or overall site-security score.",
    }
    # Backward-compatible score object with clarified semantics.
    results["score"] = {
        "percentage": percentage,
        "strong": len(present),
        "weak": len(weak),
        "missing": len(missing),
        "metric": "weighted-header-coverage",
    }
    info(
        "Header Coverage",
        f"{percentage}% weighted coverage ({len(present)} present, {len(weak)} weak, {len(missing)} required missing)",
    )
    return results
