from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section, warn


def _finding(severity, directive, issue, classification="hardening-observation"):
    return {
        "severity": severity,
        "directive": directive,
        "issue": issue,
        "classification": classification,
    }


def run(url, domain, timeout=10):
    section("CSP Deep Analyzer", "🛡️")
    results = {"findings": [], "raw_csp": None, "present": False}

    resp = safe_request(url, timeout=timeout)
    if resp is None:
        error("Could not fetch target to check CSP.")
        results["error"] = "Could not fetch target"
        return results

    csp = (
        resp.headers.get("Content-Security-Policy")
        or resp.headers.get("X-Content-Security-Policy")
        or resp.headers.get("X-WebKit-CSP")
    )
    if not csp:
        warn("No Content-Security-Policy header found (hardening observation; not proof of XSS).")
        results["findings"].append(
            _finding(
                "INFO",
                "overall",
                "Content-Security-Policy header is not configured",
            )
        )
        return results

    results["present"] = True
    results["raw_csp"] = csp
    info("Raw CSP", csp[:150] + ("..." if len(csp) > 150 else ""))

    parsed = {}
    for entry in [item.strip() for item in csp.lower().split(";") if item.strip()]:
        parts = entry.split()
        if parts:
            parsed[parts[0]] = parts[1:]

    default_src = parsed.get("default-src")
    script_src = parsed.get("script-src")
    object_src = parsed.get("object-src")
    frame_ancestors = parsed.get("frame-ancestors")

    if default_src is None:
        results["findings"].append(_finding("LOW", "default-src", "Missing default-src directive"))
    else:
        if "*" in default_src:
            results["findings"].append(_finding("MEDIUM", "default-src", "default-src allows wildcard '*'"))
        if "data:" in default_src:
            results["findings"].append(_finding("LOW", "default-src", "default-src allows data: URIs"))

    effective_script = script_src if script_src is not None else default_src
    if effective_script is None:
        results["findings"].append(
            _finding("MEDIUM", "script-src", "No script-src or default-src restriction is defined")
        )
    else:
        if "'unsafe-inline'" in effective_script:
            results["findings"].append(
                _finding(
                    "MEDIUM",
                    "script-src",
                    "Effective script policy includes 'unsafe-inline'; impact depends on nonce/hash and application context",
                )
            )
        if "'unsafe-eval'" in effective_script:
            results["findings"].append(
                _finding("MEDIUM", "script-src", "Effective script policy includes 'unsafe-eval'")
            )
        if "*" in effective_script:
            results["findings"].append(
                _finding("MEDIUM", "script-src", "Effective script policy allows wildcard '*'")
            )
        if "data:" in effective_script:
            results["findings"].append(
                _finding("MEDIUM", "script-src", "Effective script policy allows data: URIs")
            )

    if object_src is None:
        results["findings"].append(
            _finding("INFO", "object-src", "object-src is not explicitly restricted")
        )
    elif "'none'" not in object_src:
        results["findings"].append(
            _finding("LOW", "object-src", f"object-src permits: {', '.join(object_src)}")
        )

    if frame_ancestors is None:
        results["findings"].append(
            _finding(
                "INFO",
                "frame-ancestors",
                "frame-ancestors is absent; X-Frame-Options may still provide framing protection",
            )
        )

    if results["findings"]:
        print(f"\n{Colors.BOLD}  CSP Posture Observations:{Colors.RESET}")
        for item in results["findings"]:
            color = Colors.YELLOW if item["severity"] == "MEDIUM" else Colors.DIM
            warn(
                f"[{color}{item['severity']}{Colors.RESET}] "
                f"{Colors.BOLD}{item['directive']}{Colors.RESET}: {item['issue']}"
            )
    else:
        info("CSP Result", f"{Colors.GREEN}No supported CSP weakness patterns detected.{Colors.RESET}")
    return results
