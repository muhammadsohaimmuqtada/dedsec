import re
from urllib.parse import urlparse

from dedsec.core.colors import Colors
from dedsec.core.utils import append_query_param, info, safe_request, section, warn

REDIRECT_PARAMS = [
    "url", "redirect", "next", "redir", "return", "returnTo", "redirect_uri",
    "continue", "dest", "go", "target", "out", "view", "login", "callback",
    "to", "link", "location", "from", "page", "ref", "referrer", "forward",
    "jump", "redirect_to", "ReturnUrl", "returnUrl", "successUrl", "cancelUrl",
    "goto", "success_url", "failure_url", "redirectURL", "returnURL", "backUrl",
    "r", "u", "l", "uri", "path", "back",
]

ATTACKER_URL = "https://evil.example.com"
MAX_REDIRECT_HOPS = 5

META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^\s"\'>;]+)',
    re.IGNORECASE,
)
JS_LOCATION_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|location\.assign)'
    r'\s*[=(]\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _location_host(resp):
    location = resp.headers.get("Location", "") if resp else ""
    return location, (urlparse(location).hostname or "").lower()


def _is_external(host, domain):
    return bool(host and host != domain and not host.endswith(f".{domain}"))


def _follow_redirects(url, timeout, max_hops=MAX_REDIRECT_HOPS):
    """Manually follow redirect chain. Return list of (url, status, location)."""
    chain = []
    current = url
    for _ in range(max_hops):
        resp = safe_request(current, timeout=timeout, allow_redirects=False)
        if not resp:
            break
        location = resp.headers.get("Location", "")
        chain.append({"url": current, "status": resp.status_code, "location": location})
        if resp.status_code not in {301, 302, 303, 307, 308} or not location:
            break
        # Resolve relative redirects
        if location.startswith("/"):
            parsed = urlparse(current)
            current = f"{parsed.scheme}://{parsed.netloc}{location}"
        elif not location.startswith("http"):
            current = location
        else:
            current = location
    return chain


def _body_redirect_check(resp, domain):
    """Check response body for meta-refresh and JS location redirects."""
    if not resp:
        return []
    body = resp.text
    found = []
    for m in META_REFRESH_RE.findall(body):
        host = (urlparse(m).hostname or "").lower()
        if _is_external(host, domain):
            found.append({"type": "meta-refresh", "url": m, "host": host})
    for m in JS_LOCATION_RE.findall(body):
        host = (urlparse(m).hostname or "").lower()
        if _is_external(host, domain):
            found.append({"type": "js-location", "url": m, "host": host})
    return found


def run(url, domain, timeout=10):
    section("Open Redirect Check", "🚪")
    results = {
        "confirmed": [],
        "candidates": [],
        "body_redirects": [],
        "tested": 0,
        "post_tested": 0,
    }

    # Check body of the main page for embedded redirects
    base_resp = safe_request(url, timeout=timeout)
    body_redirects = _body_redirect_check(base_resp, domain)
    if body_redirects:
        for br in body_redirects:
            warn(f"Body redirect ({br['type']}): {br['url']}")
        results["body_redirects"] = body_redirects

    # Test each parameter via GET
    for param in REDIRECT_PARAMS:
        attack_url   = append_query_param(url, param, ATTACKER_URL)
        control_url  = append_query_param(url, param, f"https://{domain}/")
        results["tested"] += 1

        # Follow redirect chain for attack URL
        chain = _follow_redirects(attack_url, timeout)
        if not chain:
            print(f"{Colors.DIM}[ ] {param}: request failed{Colors.RESET}")
            continue

        first = chain[0]
        final = chain[-1]

        # Check if any hop redirects externally
        external_hop = None
        for hop in chain:
            loc_host = (urlparse(hop.get("location", "")).hostname or "").lower()
            if _is_external(loc_host, domain):
                external_hop = hop
                break

        if not external_hop:
            # Check final destination
            final_host = (urlparse(final["url"]).hostname or "").lower()
            if _is_external(final_host, domain):
                external_hop = {"url": final["url"], "location": final["url"]}

        if not external_hop:
            print(f"{Colors.DIM}[ ] {param}: no external redirect{Colors.RESET}")
            continue

        # Confirm with control URL (internal redirect)
        control_chain = _follow_redirects(control_url, timeout)
        control_stays_internal = True
        for hop in control_chain:
            loc_host = (urlparse(hop.get("location", "")).hostname or "").lower()
            if loc_host and _is_external(loc_host, domain):
                control_stays_internal = False
                break

        finding = {
            "param": param,
            "attack_url": attack_url,
            "status": first["status"],
            "location": external_hop.get("location", ""),
            "hops": len(chain),
        }

        if control_stays_internal:
            warn(f"CONFIRMED: '{param}' redirects externally via {len(chain)}-hop chain")
            results["confirmed"].append(finding)
        else:
            print(f"{Colors.DIM}[~] candidate: '{param}' redirects externally but control also redirects externally{Colors.RESET}")
            results["candidates"].append(finding)

    # POST body test for top params
    post_params = ["url", "redirect", "next", "return", "redirect_uri"]
    for param in post_params:
        results["post_tested"] += 1
        try:
            resp = safe_request(
                url, timeout=timeout, allow_redirects=False,
                method="POST",
            )
            # Re-do with requests directly for POST data
            import requests
            post_resp = requests.post(
                url,
                data={param: ATTACKER_URL},
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )
            if post_resp.status_code in {301, 302, 303, 307, 308}:
                loc = post_resp.headers.get("Location", "")
                loc_host = (urlparse(loc).hostname or "").lower()
                if _is_external(loc_host, domain):
                    warn(f"CONFIRMED via POST: '{param}' redirects externally -> {loc}")
                    results["confirmed"].append({
                        "param": f"{param} (POST)",
                        "attack_url": url,
                        "status": post_resp.status_code,
                        "location": loc,
                        "hops": 1,
                    })
        except Exception:
            pass

    if results["confirmed"]:
        info("Confirmed Open Redirects", str(len(results["confirmed"])))
    else:
        info("Confirmed Open Redirects", f"{Colors.GREEN}0{Colors.RESET}")

    if results["candidates"]:
        warn(f"{len(results['candidates'])} redirect candidate(s) need manual validation.")

    return results
