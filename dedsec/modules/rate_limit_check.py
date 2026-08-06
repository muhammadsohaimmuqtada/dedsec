import time
from urllib.parse import urljoin

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

PROBE_PATHS = ["/login", "/api/login", "/auth", "/signin"]
MAX_PROBES = 8


def _looks_like_auth_endpoint(resp, path):
    if resp is None or resp.status_code in {404, 410}:
        return False
    text = (resp.text or "")[:3000].lower()
    indicators = ("login", "sign in", "signin", "password", "username", "email")
    return any(token in text for token in indicators) or path in ("/login", "/signin") and resp.status_code in {200, 401, 403, 405}


def _rate_headers(resp):
    found = {}
    if resp is None:
        return found
    for key, value in resp.headers.items():
        lower = key.lower()
        if "ratelimit" in lower or lower in {"retry-after", "x-rate-limit", "x-ratelimit-limit", "x-ratelimit-remaining"}:
            found[key] = value
    return found


def run(url, domain, timeout=10):
    section("Rate Limit Observation", "📡")
    results = {
        "endpoint_tested": None,
        "requests_sent": 0,
        "rate_limited": False,
        "limit_after": None,
        "rate_limit_headers": {},
        "status_codes": [],
        "assessment": "inconclusive",
        "findings": [],
        "observations": [],
    }

    test_url = None
    for path in PROBE_PATHS:
        candidate = urljoin(url, path)
        resp = safe_request(candidate, timeout=timeout, allow_redirects=False, cache=False)
        if _looks_like_auth_endpoint(resp, path):
            test_url = candidate
            break

    if test_url is None:
        warn("No likely authentication endpoint was positively identified; rate-limit probe skipped.")
        results["observations"].append(
            {
                "type": "rate-limit",
                "result": "skipped",
                "reason": "no likely authentication endpoint identified",
            }
        )
        return results

    results["endpoint_tested"] = test_url
    print(f"  Observing throttling behavior on '{test_url}' with up to {MAX_PROBES} bounded GET requests...")

    first_latency = None
    last_latency = None
    for index in range(MAX_PROBES):
        started = time.monotonic()
        resp = safe_request(
            test_url,
            timeout=timeout,
            allow_redirects=False,
            cache=False,
            headers={"User-Agent": "DEDSEC-Recon/1.3"},
        )
        elapsed = time.monotonic() - started
        if first_latency is None:
            first_latency = elapsed
        last_latency = elapsed
        results["requests_sent"] += 1

        if resp is None:
            results["status_codes"].append(None)
            continue

        results["status_codes"].append(resp.status_code)
        results["rate_limit_headers"].update(_rate_headers(resp))
        if resp.status_code == 429:
            results["rate_limited"] = True
            results["limit_after"] = index + 1
            break
        time.sleep(0.1)

    if results["rate_limited"]:
        results["assessment"] = "throttling-observed"
        info(
            "Rate Limiting",
            f"{Colors.GREEN}Observed HTTP 429 after {results['limit_after']} request(s){Colors.RESET}",
        )
    elif results["rate_limit_headers"]:
        results["assessment"] = "rate-limit-signals-observed"
        info(
            "Rate Limit Headers",
            ", ".join(f"{k}: {v}" for k, v in results["rate_limit_headers"].items()),
        )
    else:
        # Absence of a 429 in a tiny anonymous sample cannot establish that
        # brute-force protection is missing. Keep this as an observation only.
        results["assessment"] = "no-throttling-observed-in-bounded-sample"
        results["observations"].append(
            {
                "type": "rate-limit",
                "result": "not-observed",
                "sample_size": results["requests_sent"],
                "endpoint": test_url,
                "note": "No HTTP throttling signal observed in this bounded anonymous sample; this is not proof that abuse protection is absent.",
            }
        )
        warn(
            "No HTTP throttling signal observed in the bounded sample; treating as an observation, not a vulnerability."
        )

    if first_latency is not None and last_latency is not None:
        results["latency"] = {
            "first_seconds": round(first_latency, 3),
            "last_seconds": round(last_latency, 3),
        }
    return results
