from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import cached_resolve_ipv4, info, safe_request, section, warn

VHOST_SUBDOMAINS = [
    "dev", "staging", "internal", "admin", "test", "stage", "uat",
    "portal", "api", "app", "corp", "mgmt", "console", "private",
]


def _signature(response):
    text = response.text or ""
    return {
        "status": response.status_code,
        "length": len(text),
        "location": response.headers.get("Location", ""),
    }


def _distinct(candidate, baseline):
    if candidate["status"] != baseline["status"]:
        return True
    base_length = max(baseline["length"], 1)
    if abs(candidate["length"] - baseline["length"]) / base_length > 0.20:
        return True
    return candidate["location"] != baseline["location"]


def run(url, domain, timeout=10):
    section("Virtual Host Candidate Finder", "🖥️")
    results = {
        "vhosts_found": [],
        "candidates": [],
        "ip_tested": None,
        "transport_failures": 0,
        "probe_scheme": "http",
        "partial": False,
        "inconclusive": False,
    }
    ip = cached_resolve_ipv4(domain)
    if not ip:
        warn(f"Could not resolve target IP for {domain}.")
        results["inconclusive"] = True
        results["error"] = "Could not resolve target IP"
        results["failure_class"] = "dns"
        return results
    results["ip_tested"] = ip
    info("Target IP Address", ip)

    # Keep the URL host in canonical scope so the shared v2 transport enforces
    # target budget/scope. The Host header is varied while DNS still resolves the
    # canonical target; no TLS verification is disabled or bypassed.
    base_target = f"http://{domain}/"
    base_response = safe_request(
        base_target,
        headers={"Host": domain},
        timeout=timeout,
        allow_redirects=False,
        cache=False,
    )
    if base_response is None:
        warn("Could not obtain an in-scope HTTP baseline; vhost discovery is inconclusive.")
        results["transport_failures"] += 1
        results["inconclusive"] = True
        results["error"] = "Could not obtain in-scope HTTP baseline"
        results["failure_class"] = "target_transport"
        return results
    baseline = _signature(base_response)

    print(f"  Comparing bounded Host-header responses for {domain} ({ip})...")

    def _test(prefix):
        vhost = f"{prefix}.{domain}"
        response = safe_request(
            base_target,
            headers={"Host": vhost},
            timeout=timeout,
            allow_redirects=False,
            cache=False,
        )
        if response is None:
            return {"vhost": vhost, "transport_failure": True}
        signature = _signature(response)
        if not _distinct(signature, baseline):
            return None
        return {
            "vhost": vhost,
            "status": signature["status"],
            "length": signature["length"],
            "location": signature["location"],
            "base_status": baseline["status"],
            "base_length": baseline["length"],
            "classification": "response-difference-candidate",
            "verified": False,
        }

    candidates = []
    with ThreadPoolExecutor(max_workers=min(8, len(VHOST_SUBDOMAINS))) as executor:
        futures = [executor.submit(_test, prefix) for prefix in VHOST_SUBDOMAINS]
        for future in as_completed(futures):
            item = future.result()
            if item and item.get("transport_failure"):
                results["transport_failures"] += 1
            elif item:
                candidates.append(item)

    candidates.sort(key=lambda item: item["vhost"])
    results["candidates"] = candidates
    results["vhosts_found"] = candidates
    if results["transport_failures"]:
        results["partial"] = True
        results["error"] = (
            f"{results['transport_failures']} Host-header probe(s) failed at transport level"
        )
        results["failure_class"] = "partial_transport"
    if candidates:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} {Colors.BOLD}VHost Response-Difference Candidates:{Colors.RESET}")
        for item in candidates:
            warn(
                f"Candidate {item['vhost']}: status {item['status']} vs {item['base_status']}, "
                f"length {item['length']} vs {item['base_length']} (not DNS/ownership verified)"
            )
    elif not results["partial"]:
        info("VHost Check", f"{Colors.GREEN}No distinct Host-header responses identified on {domain}{Colors.RESET}")
    return results
