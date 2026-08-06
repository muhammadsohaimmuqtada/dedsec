import re
from urllib.parse import urljoin, urlparse

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


def _is_external(host, domain):
    return bool(host and host != domain and not host.endswith(f".{domain}"))


def _follow_redirects(start_url, domain, timeout, max_hops=MAX_REDIRECT_HOPS):
    """Follow only in-scope hops and stop before contacting an external host."""
    chain = []
    current = start_url
    for _ in range(max_hops):
        resp = safe_request(current, timeout=timeout, allow_redirects=False, cache=False)
        if resp is None:
            break
        location = resp.headers.get("Location", "")
        absolute_location = urljoin(current, location) if location else ""
        location_host = (urlparse(absolute_location).hostname or "").lower()
        chain.append(
            {
                "url": current,
                "status": resp.status_code,
                "location": location,
                "absolute_location": absolute_location,
                "external": _is_external(location_host, domain),
            }
        )
        if resp.status_code not in {301, 302, 303, 307, 308} or not location:
            break
        if _is_external(location_host, domain):
            # Evidence is the Location header returned by the in-scope target.
            # Never follow the browser to the external destination.
            break
        current = absolute_location
    return chain


def _body_redirect_check(resp, domain):
    if resp is None:
        return []
    body = resp.text
    found = []
    for value in META_REFRESH_RE.findall(body):
        host = (urlparse(value).hostname or "").lower()
        if _is_external(host, domain):
            found.append({"type": "meta-refresh", "url": value, "host": host})
    for value in JS_LOCATION_RE.findall(body):
        host = (urlparse(value).hostname or "").lower()
        if _is_external(host, domain):
            found.append({"type": "js-location", "url": value, "host": host})
    return found


def _external_hop(chain):
    return next((hop for hop in chain if hop.get("external")), None)


def run(url, domain, timeout=10):
    section("Open Redirect Check", "🚪")
    results = {
        "confirmed": [],
        "candidates": [],
        "body_redirects": [],
        "tested": 0,
        "post_tested": 0,
        "transport_failures": 0,
    }

    base_resp = safe_request(url, timeout=timeout)
    body_redirects = _body_redirect_check(base_resp, domain)
    if body_redirects:
        # Static redirects can be intentional; record as surface observations.
        results["body_redirects"] = body_redirects
        for item in body_redirects:
            warn(f"Body redirect observation ({item['type']}): {item['url']}")

    for param in REDIRECT_PARAMS:
        attack_url = append_query_param(url, param, ATTACKER_URL)
        control_url = append_query_param(url, param, f"https://{domain}/")
        results["tested"] += 1

        attack_chain = _follow_redirects(attack_url, domain, timeout)
        if not attack_chain:
            results["transport_failures"] += 1
            print(f"{Colors.DIM}[ ] {param}: transport failure{Colors.RESET}")
            continue

        attack_external = _external_hop(attack_chain)
        if not attack_external:
            print(f"{Colors.DIM}[ ] {param}: no external redirect{Colors.RESET}")
            continue

        control_chain = _follow_redirects(control_url, domain, timeout)
        control_external = _external_hop(control_chain)
        finding = {
            "param": param,
            "attack_url": attack_url,
            "status": attack_external["status"],
            "location": attack_external.get("location", ""),
            "hops": len(attack_chain),
            "control_external": bool(control_external),
        }

        if control_chain and control_external is None:
            warn(f"CONFIRMED: '{param}' produced an attacker-controlled external Location header")
            results["confirmed"].append(finding)
        else:
            results["candidates"].append(finding)
            print(
                f"{Colors.DIM}[~] candidate: '{param}' external redirect was not isolated from control behavior{Colors.RESET}"
            )

    # Bounded POST validation with an explicit internal negative control.
    for param in ["url", "redirect", "next", "return", "redirect_uri"]:
        results["post_tested"] += 1
        attack_resp = safe_request(
            url,
            timeout=timeout,
            allow_redirects=False,
            method="POST",
            data={param: ATTACKER_URL},
            cache=False,
        )
        control_resp = safe_request(
            url,
            timeout=timeout,
            allow_redirects=False,
            method="POST",
            data={param: f"https://{domain}/"},
            cache=False,
        )
        if attack_resp is None or control_resp is None:
            results["transport_failures"] += 1
            continue

        attack_location = attack_resp.headers.get("Location", "")
        attack_host = (urlparse(urljoin(url, attack_location)).hostname or "").lower()
        control_location = control_resp.headers.get("Location", "")
        control_host = (urlparse(urljoin(url, control_location)).hostname or "").lower()
        if (
            attack_resp.status_code in {301, 302, 303, 307, 308}
            and _is_external(attack_host, domain)
            and not _is_external(control_host, domain)
        ):
            warn(f"CONFIRMED via POST: '{param}' returns external Location -> {attack_location}")
            results["confirmed"].append(
                {
                    "param": f"{param} (POST)",
                    "attack_url": url,
                    "status": attack_resp.status_code,
                    "location": attack_location,
                    "hops": 1,
                    "control_external": False,
                }
            )

    info("Confirmed Open Redirects", str(len(results["confirmed"])))
    if results["candidates"]:
        warn(f"{len(results['candidates'])} redirect candidate(s) need manual validation.")
    if results["transport_failures"]:
        warn(f"{results['transport_failures']} redirect probe(s) had transport failures.")
    return results
