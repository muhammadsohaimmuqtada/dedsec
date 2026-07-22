from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error

def run(url, domain, timeout=10):
    section("Clickjacking embedding test", "🖼️")
    results = {"findings": [], "xfo_header": None, "csp_frame_ancestors": None, "vulnerable": False}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not fetch target to check clickjacking.")
        return results

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    
    # Check X-Frame-Options
    xfo = headers_lower.get("x-frame-options")
    results["xfo_header"] = xfo

    # Check CSP frame-ancestors directive
    csp = headers_lower.get("content-security-policy", "")
    frame_ancestors = None
    for directive in csp.split(";"):
        directive = directive.strip().lower()
        if directive.startswith("frame-ancestors"):
            frame_ancestors = directive
            break
    results["csp_frame_ancestors"] = frame_ancestors

    if xfo:
        info("X-Frame-Options Header", xfo)
    if frame_ancestors:
        info("CSP frame-ancestors Directive", frame_ancestors)

    # Clickjacking protection logic
    protected = False
    
    # 1. Check CSP first (modern browsers prefer frame-ancestors)
    if frame_ancestors:
        parts = frame_ancestors.split()
        sources = parts[1:]
        if "'none'" in sources or "'self'" in sources:
            protected = True
            info("Clickjacking Protection", f"{Colors.GREEN}SECURE (enforced by CSP frame-ancestors){Colors.RESET}")
        else:
            warn(f"CSP frame-ancestors allows framing: {', '.join(sources)}")
            results["findings"].append({
                "severity": "LOW",
                "issue": f"CSP frame-ancestors is permissive: {frame_ancestors}"
            })

    # 2. Check XFO as fallback
    if not protected:
        if xfo:
            xfo_lower = xfo.lower().strip()
            if xfo_lower in ("deny", "sameorigin"):
                protected = True
                info("Clickjacking Protection", f"{Colors.GREEN}SECURE (enforced by X-Frame-Options){Colors.RESET}")
            else:
                warn(f"X-Frame-Options header value '{xfo}' is invalid/weak. Expected DENY or SAMEORIGIN.")
                results["findings"].append({
                    "severity": "MEDIUM",
                    "issue": f"Weak X-Frame-Options header configuration: {xfo}"
                })

    if not protected:
        warn("Target is vulnerable to clickjacking! No framing restriction headers found.")
        results["findings"].append({
            "severity": "MEDIUM",
            "issue": "Missing framing protection (neither X-Frame-Options nor frame-ancestors CSP directive present)"
        })
        results["vulnerable"] = True

    return results
