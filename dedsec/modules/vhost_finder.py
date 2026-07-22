import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from dedsec.core.colors import Colors
from dedsec.core.utils import cached_resolve_ipv4, section, info, warn, error, _get_headers

VHOST_SUBDOMAINS = [
    "dev", "staging", "internal", "admin", "test", "stage", "uat",
    "portal", "api", "app", "corp", "mgmt", "console", "private"
]

def run(url, domain, timeout=10):
    section("Virtual Host Finder", "🖥️")
    results = {"vhosts_found": [], "ip_tested": None}

    ip = cached_resolve_ipv4(domain)
    if not ip:
        error(f"Could not resolve target IP for {domain}.")
        return results

    results["ip_tested"] = ip
    info("Target IP Address", ip)

    scheme = urlparse(url).scheme or "https"
    base_target = f"{scheme}://{ip}"

    # Get baseline response connecting directly to IP
    try:
        base_resp = requests.get(base_target, headers={"Host": domain, **_get_headers()}, timeout=timeout, verify=False)
        base_status = base_resp.status_code
        base_len = len(base_resp.text)
    except Exception:
        warn("Failed to obtain baseline response from direct IP connection.")
        return results

    print(f"  Fuzzing Host headers on {ip} for domain {domain}...")
    vhosts_found = []

    def _test_vhost(prefix):
        vhost_name = f"{prefix}.{domain}"
        try:
            resp = requests.get(
                base_target,
                headers={"Host": vhost_name, **_get_headers()},
                timeout=timeout,
                verify=False
            )
            len_diff = abs(len(resp.text) - base_len)
            # If status code changes or body length changes significantly (>15% diff)
            if resp.status_code != base_status or len_diff > (base_len * 0.15):
                return {
                    "vhost": vhost_name,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "base_status": base_status,
                    "base_length": base_len
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_test_vhost, prefix): prefix for prefix in VHOST_SUBDOMAINS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                vhosts_found.append(res)

    results["vhosts_found"] = vhosts_found
    if vhosts_found:
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Virtual Hosts Discovered:{Colors.RESET}")
        for v in vhosts_found:
            warn(f"Discovered VHost: {Colors.CYAN}{v['vhost']}{Colors.RESET} (Status {v['status']} vs Base {v['base_status']}, Length {v['length']} vs Base {v['base_length']})")
    else:
        info("VHost Check", f"{Colors.GREEN}No distinct virtual hosts identified on IP {ip}{Colors.RESET}")

    return results
