from urllib.parse import urlparse

from dedsec.core.colors import Colors
from dedsec.core.utils import append_query_param, info, safe_request, section, warn

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "redir",
    "return",
    "returnTo",
    "redirect_uri",
    "continue",
    "dest",
    "go",
    "target",
    "out",
    "view",
    "login",
    "callback",
]

ATTACKER_URL = "https://evil.example"


def _location_host(resp):
    location = resp.headers.get("Location", "") if resp else ""
    return location, (urlparse(location).hostname or "").lower()


def _is_external_redirect(host, domain):
    return bool(host and host != domain and not host.endswith(f".{domain}"))


def run(url, domain, timeout=10):
    section("Open Redirect Check", "🚪")
    results = {"confirmed": [], "candidates": [], "tested": 0}

    for param in REDIRECT_PARAMS:
        attack_url = append_query_param(url, param, ATTACKER_URL)
        control_url = append_query_param(url, param, f"https://{domain}/")
        results["tested"] += 1

        attack_resp = safe_request(attack_url, timeout=timeout, allow_redirects=False)
        if not attack_resp:
            print(f"{Colors.DIM}[ ] {param}: request failed{Colors.RESET}")
            continue

        attack_location, attack_host = _location_host(attack_resp)
        if attack_resp.status_code not in {301, 302, 303, 307, 308}:
            print(f"{Colors.DIM}[ ] {param}: {attack_resp.status_code} (no redirect){Colors.RESET}")
            continue

        if not _is_external_redirect(attack_host, domain):
            print(f"{Colors.DIM}[ ] {param}: redirects internally{Colors.RESET}")
            continue

        control_resp = safe_request(control_url, timeout=timeout, allow_redirects=False)
        control_location, control_host = _location_host(control_resp) if control_resp else ("", "")

        finding = {
            "param": param,
            "attack_url": attack_url,
            "status": attack_resp.status_code,
            "location": attack_location,
            "control_location": control_location,
        }

        if control_resp and control_resp.status_code in {301, 302, 303, 307, 308} and control_host == domain:
            warn(f"CONFIRMED: parameter '{param}' performs external redirect to {attack_host}")
            results["confirmed"].append(finding)
        else:
            print(f"{Colors.DIM}[~] candidate: {param} redirects externally but control behavior is inconsistent{Colors.RESET}")
            results["candidates"].append(finding)

    if results["confirmed"]:
        info("Confirmed Open Redirects", str(len(results["confirmed"])))
    else:
        info("Confirmed Open Redirects", f"{Colors.GREEN}0{Colors.RESET}")

    if results["candidates"]:
        warn(f"{len(results['candidates'])} redirect candidate(s) require manual validation.")

    return results
