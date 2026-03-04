from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors


def _parse_set_cookie_headers(response):
    """Parse raw Set-Cookie headers to reliably detect HttpOnly, Secure, and SameSite flags."""
    raw_headers = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
    if not raw_headers:
        # Fallback: collect all Set-Cookie values from urllib3 response
        try:
            raw_headers = [v for k, v in response.raw.headers.items() if k.lower() == "set-cookie"]
        except Exception:
            raw_headers = []

    parsed = {}
    for header in raw_headers:
        parts = [p.strip() for p in header.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        eq = name_val.find("=")
        if eq == -1:
            continue
        name = name_val[:eq].strip()
        value = name_val[eq+1:].strip()
        attrs_lower = [p.lower() for p in parts[1:]]
        has_httponly = "httponly" in attrs_lower
        has_secure   = "secure" in attrs_lower
        samesite = "Not Set"
        for attr in parts[1:]:
            if attr.strip().lower().startswith("samesite"):
                samesite = attr.split("=", 1)[1].strip() if "=" in attr else "present"
                break
        parsed[name] = {
            "value": value,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite,
        }
    return parsed


def run(url, domain, timeout=10):
    section("Cookie Audit", "🍪")
    results = {"cookies": [], "issues": []}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    cookies = resp.cookies

    if not cookies:
        warn("No cookies set by the server.")
        results["count"] = 0
        return results

    info("Cookies Found", str(len(cookies)))

    # Parse raw headers for accurate flag detection
    raw_parsed = _parse_set_cookie_headers(resp)

    cookie_list = []
    all_issues = []

    for cookie in cookies:
        name = cookie.name
        value = cookie.value or ""
        truncated_val = value[:30] + "..." if len(value) > 30 else value
        c_domain = cookie.domain or domain
        c_path = cookie.path or "/"

        # Use raw header parse if available, fall back to requests attributes
        raw = raw_parsed.get(name, {})
        has_httponly = raw.get("httponly", cookie.has_nonstandard_attr("HttpOnly"))
        has_secure   = raw.get("secure", cookie.secure)
        samesite     = raw.get("samesite", "Not Set")

        print(f"\n  {Colors.BOLD}{Colors.CYAN}Cookie: {name}{Colors.RESET}")
        print(f"    Value   : {Colors.DIM}{truncated_val}{Colors.RESET}")
        print(f"    Domain  : {c_domain}")
        print(f"    Path    : {c_path}")

        issues = []

        if has_httponly:
            print(f"    HttpOnly: {Colors.GREEN}✔ Yes{Colors.RESET}")
        else:
            print(f"    HttpOnly: {Colors.RED}✘ Missing{Colors.RESET}  ← vulnerable to XSS cookie theft")
            issues.append("Missing HttpOnly — cookie accessible via JavaScript (XSS risk)")

        if has_secure:
            print(f"    Secure  : {Colors.GREEN}✔ Yes{Colors.RESET}")
        else:
            print(f"    Secure  : {Colors.RED}✘ Missing{Colors.RESET}  ← transmitted over HTTP (MITM risk)")
            issues.append("Missing Secure flag — cookie sent over unencrypted HTTP (MITM risk)")

        if samesite.lower() in ("strict", "lax"):
            print(f"    SameSite: {Colors.GREEN}✔ {samesite}{Colors.RESET}")
        elif samesite.lower() == "none":
            print(f"    SameSite: {Colors.YELLOW}⚠ None{Colors.RESET}  ← cross-site requests allowed")
            issues.append("SameSite=None — cookie sent on all cross-site requests (CSRF risk)")
        else:
            print(f"    SameSite: {Colors.RED}✘ {samesite}{Colors.RESET}  ← CSRF risk (no SameSite protection)")
            issues.append(f"Missing SameSite attribute — susceptible to CSRF attacks")

        entry = {
            "name": name,
            "value_truncated": truncated_val,
            "domain": c_domain,
            "path": c_path,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite,
            "issues": issues,
        }
        cookie_list.append(entry)
        all_issues.extend(issues)

    results["cookies"] = cookie_list
    results["issues"] = all_issues
    results["count"] = len(cookie_list)

    if all_issues:
        warn(f"Total security issues found: {len(all_issues)}")
    else:
        info("Result", f"{Colors.GREEN}All cookies appear properly configured{Colors.RESET}")

    return results
