from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error

def run(url, domain, timeout=10):
    section("CSP Deep Analyzer", "🛡️")
    results = {"findings": [], "raw_csp": None}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not fetch target to check CSP.")
        return results

    csp = resp.headers.get("Content-Security-Policy")
    if not csp:
        # Check alternative headers
        csp = resp.headers.get("X-Content-Security-Policy") or resp.headers.get("X-WebKit-CSP")

    if not csp:
        warn("No Content-Security-Policy header found!")
        results["findings"].append({
            "severity": "HIGH",
            "issue": "Missing Content-Security-Policy header",
            "directive": "overall"
        })
        return results

    results["raw_csp"] = csp
    info("Raw CSP", csp[:150] + ("..." if len(csp) > 150 else ""))

    directives = [d.strip() for d in csp.lower().split(";") if d.strip()]
    
    default_src = None
    script_src = None
    style_src = None
    object_src = None
    frame_ancestors = None

    for dir_entry in directives:
        parts = dir_entry.split()
        if not parts:
            continue
        dir_name = parts[0]
        sources = parts[1:]

        if dir_name == "default-src":
            default_src = sources
        elif dir_name == "script-src":
            script_src = sources
        elif dir_name == "style-src":
            style_src = sources
        elif dir_name == "object-src":
            object_src = sources
        elif dir_name == "frame-ancestors":
            frame_ancestors = sources

    # Directives checks
    # 1. default-src
    if not default_src:
        results["findings"].append({
            "severity": "MEDIUM",
            "directive": "default-src",
            "issue": "Missing default-src directive"
        })
    else:
        if "*" in default_src:
            results["findings"].append({
                "severity": "MEDIUM",
                "directive": "default-src",
                "issue": "Allows wildcard '*' in default-src"
            })
        if "data:" in default_src:
            results["findings"].append({
                "severity": "MEDIUM",
                "directive": "default-src",
                "issue": "Allows 'data:' URIs in default-src (enables XSS bypasses)"
            })

    # 2. script-src
    if not script_src:
        if not default_src:
            results["findings"].append({
                "severity": "HIGH",
                "directive": "script-src",
                "issue": "No script-src or default-src defined (XSS protection absent)"
            })
    else:
        if "unsafe-inline" in script_src:
            results["findings"].append({
                "severity": "HIGH",
                "directive": "script-src",
                "issue": "Allows 'unsafe-inline' (allows execution of inline scripts, bypassing CSP protection)"
            })
        if "unsafe-eval" in script_src:
            results["findings"].append({
                "severity": "HIGH",
                "directive": "script-src",
                "issue": "Allows 'unsafe-eval' (allows execution of arbitrary string inputs)"
            })
        if "*" in script_src:
            results["findings"].append({
                "severity": "HIGH",
                "directive": "script-src",
                "issue": "Allows wildcard '*' (allows scripts to be loaded from any origin)"
            })
        if "data:" in script_src:
            results["findings"].append({
                "severity": "MEDIUM",
                "directive": "script-src",
                "issue": "Allows 'data:' URIs (allows inline payload injection)"
            })

    # 3. object-src
    if not object_src:
        results["findings"].append({
            "severity": "LOW",
            "directive": "object-src",
            "issue": "Missing object-src (should be restricted to 'none' to prevent Flash/Java applet injection)"
        })
    elif "none" not in object_src:
        results["findings"].append({
            "severity": "LOW",
            "directive": "object-src",
            "issue": f"object-src allows active plugin elements: {', '.join(object_src)}"
        })

    # 4. frame-ancestors
    if not frame_ancestors:
        results["findings"].append({
            "severity": "LOW",
            "directive": "frame-ancestors",
            "issue": "Missing frame-ancestors (allows clickjacking protection fallback to X-Frame-Options only)"
        })

    if results["findings"]:
        print(f"\n{Colors.BOLD}  CSP Weaknesses Found:{Colors.RESET}")
        for f in results["findings"]:
            color = Colors.RED if f["severity"] in ("HIGH", "CRITICAL") else Colors.YELLOW if f["severity"] == "MEDIUM" else Colors.DIM
            warn(f"[{color}{f['severity']}{Colors.RESET}] {Colors.BOLD}{f['directive']}{Colors.RESET}: {f['issue']}")
    else:
        info("CSP Result", f"{Colors.GREEN}CSP is strong and well-configured.{Colors.RESET}")

    return results
