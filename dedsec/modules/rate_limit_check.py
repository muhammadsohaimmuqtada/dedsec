import time
from urllib.parse import urljoin
from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error
import requests

PROBE_PATHS = ["/login", "/api/login", "/auth", "/signin", "/search", "/api/search"]

def run(url, domain, timeout=10):
    section("Rate Limit Detection Check", "📡")
    results = {"endpoint_tested": None, "requests_sent": 0, "rate_limited": False, "limit_after": None, "findings": []}

    # Find a valid endpoint to probe
    test_url = url
    for path in PROBE_PATHS:
        candidate = urljoin(url, path)
        try:
            resp = requests.post(candidate, data={"username": "test", "password": "test"}, timeout=timeout, verify=False)
            if resp.status_code in {200, 400, 401, 403, 405}:
                test_url = candidate
                break
        except Exception:
            pass

    results["endpoint_tested"] = test_url
    print(f"  Testing rate limiting on '{test_url}' using 20 rapid sequential requests...")

    status_codes = []
    ratelimit_headers_found = {}
    rate_limited = False
    limit_after = None

    for i in range(20):
        results["requests_sent"] += 1
        try:
            # We send lightweight POST requests
            resp = requests.post(
                test_url, 
                data={"user": f"dedsec_test_{i}", "pass": "test"}, 
                timeout=timeout, 
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 DEDSEC-Recon/1.0"}
            )
            status_codes.append(resp.status_code)
            
            # Check rate limiting headers
            for h, v in resp.headers.items():
                if any(x in h.lower() for x in ("ratelimit", "retry-after")):
                    ratelimit_headers_found[h] = v

            if resp.status_code == 429:
                rate_limited = True
                if limit_after is None:
                    limit_after = i + 1

        except Exception as e:
            pass
        time.sleep(0.05) # short buffer

    results["rate_limited"] = rate_limited
    results["limit_after"] = limit_after

    if ratelimit_headers_found:
        info("Rate Limit Headers Found", ", ".join(f"{k}: {v}" for k, v in ratelimit_headers_found.items()))

    if rate_limited:
        info("Rate Limiting", f"{Colors.GREEN}Active (blocked after {limit_after} requests with status 429){Colors.RESET}")
    else:
        warn("No rate limiting detected on auth/sensitive endpoints! Vulnerable to brute-force or abuse.")
        results["findings"].append({
            "severity": "HIGH",
            "issue": "Missing rate limit protection on login/sensitive endpoint"
        })

    return results
