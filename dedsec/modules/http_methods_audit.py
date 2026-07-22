from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error

METHODS_TO_TEST = ["OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT"]

def run(url, domain, timeout=10):
    section("Dangerous HTTP Methods Audit", "🛠️")
    results = {"allowed_methods": [], "risks": []}

    print(f"  Testing HTTP methods on {url}...")
    
    # 1. Test OPTIONS header
    options_resp = safe_request(url, timeout=timeout, method="OPTIONS")
    allow_header = options_resp.headers.get("Allow") or options_resp.headers.get("Access-Control-Allow-Methods") if options_resp else None
    
    if allow_header:
        info("Allowed Methods Header (Allow)", allow_header)
        results["allow_header"] = allow_header

    # 2. Test individual methods directly
    for method in METHODS_TO_TEST:
        resp = safe_request(url, timeout=timeout, method=method)
        if not resp:
            continue

        status = resp.status_code
        if status not in (405, 501, 400, 403):
            results["allowed_methods"].append({"method": method, "status": status})

            if method == "TRACE" and status == 200:
                error("CRITICAL: HTTP TRACE method enabled (Cross-Site Tracing XST risk)!")
                results["risks"].append("HTTP TRACE enabled (XST risk)")
            elif method == "PUT" and status in (200, 201, 204):
                warn(f"HIGH: HTTP PUT method returned status {status} (potential arbitrary file write)!")
                results["risks"].append(f"HTTP PUT enabled ({status})")
            elif method == "DELETE" and status in (200, 202, 204):
                warn(f"HIGH: HTTP DELETE method returned status {status}!")
                results["risks"].append(f"HTTP DELETE enabled ({status})")
            else:
                print(f"  {Colors.YELLOW}\u26a0{Colors.RESET}  Method {method} returned non-blocked status {status}")

    if not results["risks"] and not results["allowed_methods"]:
        info("HTTP Methods Audit", f"{Colors.GREEN}Non-standard methods properly blocked or restricted.{Colors.RESET}")

    return results
