from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section, warn


def run(url, domain, timeout=10):
    section("Clickjacking Framing Posture", "🖼️")
    results = {
        "findings": [],
        "observations": [],
        "xfo_header": None,
        "csp_frame_ancestors": None,
        "protected": False,
        "vulnerable": False,
    }

    response = safe_request(url, timeout=timeout)
    if response is None:
        error("Could not fetch target to check framing posture.")
        results["error"] = "Could not fetch target"
        return results

    headers = {key.lower(): value for key, value in response.headers.items()}
    xfo = headers.get("x-frame-options")
    results["xfo_header"] = xfo

    csp = headers.get("content-security-policy", "")
    frame_ancestors = None
    for directive in csp.split(";"):
        directive = directive.strip().lower()
        if directive.startswith("frame-ancestors"):
            frame_ancestors = directive
            break
    results["csp_frame_ancestors"] = frame_ancestors

    protected = False
    if frame_ancestors:
        info("CSP frame-ancestors", frame_ancestors)
        sources = frame_ancestors.split()[1:]
        if "'none'" in sources or "'self'" in sources:
            protected = True
        else:
            results["observations"].append(
                {
                    "type": "framing-policy",
                    "result": "permissive-csp",
                    "value": frame_ancestors,
                    "note": "Permissive framing policy observed; UI impact was not demonstrated.",
                }
            )

    if xfo:
        info("X-Frame-Options", xfo)
        if xfo.lower().strip() in {"deny", "sameorigin"}:
            protected = True
        elif not protected:
            results["observations"].append(
                {
                    "type": "framing-policy",
                    "result": "nonstandard-xfo",
                    "value": xfo,
                    "note": "Nonstandard X-Frame-Options value; browser behavior should be validated.",
                }
            )

    results["protected"] = protected
    if protected:
        info("Framing Protection", f"{Colors.GREEN}Restriction header observed{Colors.RESET}")
    else:
        # Header absence establishes potential frameability, not a complete
        # clickjacking vulnerability. Meaningful UI/action impact is separate.
        observation = {
            "type": "potential-frameability",
            "severity": "INFO",
            "issue": "No effective X-Frame-Options or CSP frame-ancestors restriction observed",
            "note": "Potential frameability is a hardening observation; clickjacking impact was not demonstrated.",
        }
        results["observations"].append(observation)
        warn("No effective framing restriction observed; recording potential frameability, not a verified clickjacking vulnerability.")

    # Kept for report-schema compatibility. This module never sets it True from
    # headers alone because no meaningful UI action has been demonstrated.
    results["vulnerable"] = False
    return results
