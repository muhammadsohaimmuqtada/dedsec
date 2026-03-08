import json
import socket

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

MAX_CRT_RESULTS = 300
MAX_DISPLAY = 50


def _resolve(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except Exception:
        return None


def _probe_alive(subdomain, timeout):
    for scheme in ("https", "http"):
        target = f"{scheme}://{subdomain}"
        resp = safe_request(target, timeout=timeout, allow_redirects=False)
        if resp and resp.status_code < 500:
            return {"url": target, "status": resp.status_code}
    return None


def run(url, domain, timeout=10):
    section("Subdomain Enumeration", "🌐")
    results = {
        "source": "crt.sh (Certificate Transparency)",
        "discovered_count": 0,
        "resolved_count": 0,
        "alive_count": 0,
        "resolved": [],
        "alive": [],
    }

    api_url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = safe_request(api_url, timeout=timeout)
    if not resp:
        warn("crt.sh lookup failed.")
        return results

    try:
        data = resp.json()
    except json.JSONDecodeError:
        warn("crt.sh response was not valid JSON.")
        return results

    discovered = set()
    for entry in data[:MAX_CRT_RESULTS]:
        names = entry.get("name_value", "")
        for name in names.splitlines():
            candidate = name.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if not candidate.endswith(f".{domain}"):
                continue
            if candidate in {domain, f"www.{domain}"}:
                continue
            discovered.add(candidate)

    results["discovered_count"] = len(discovered)
    if not discovered:
        warn("No subdomains found via certificate transparency.")
        return results

    info("Discovered (raw)", str(len(discovered)))
    resolved = []
    alive = []

    for subdomain in sorted(discovered):
        ip = _resolve(subdomain)
        if not ip:
            continue
        resolved.append({"subdomain": subdomain, "ip": ip})
        probe = _probe_alive(subdomain, timeout)
        if probe:
            alive.append({"subdomain": subdomain, "ip": ip, "url": probe["url"], "status": probe["status"]})

    results["resolved_count"] = len(resolved)
    results["alive_count"] = len(alive)
    results["resolved"] = resolved[:MAX_DISPLAY]
    results["alive"] = alive[:MAX_DISPLAY]

    info("Resolved", str(len(resolved)))
    info("Alive Web Hosts", str(len(alive)))

    if alive:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Validated subdomains (showing up to {MAX_DISPLAY}):{Colors.RESET}")
        for item in alive[:MAX_DISPLAY]:
            print(f"       {Colors.CYAN}• {item['subdomain']} -> {item['ip']} ({item['status']}){Colors.RESET}")
        if len(alive) > MAX_DISPLAY:
            warn(f"Showing {MAX_DISPLAY} of {len(alive)} alive subdomains.")
    else:
        warn("No live web subdomains validated.")

    return results
