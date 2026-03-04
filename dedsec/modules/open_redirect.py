import requests
import urllib3
from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REDIRECT_PARAMS = [
    "url", "redirect", "next", "redir", "return", "returnTo", "redirect_uri",
    "continue", "dest", "go", "target", "out", "view", "login", "callback",
]

EVIL_URL = "https://evil.com"


def run(url, domain, timeout=10):
    section("Open Redirect Check", "🚪")
    results = {"vulnerable": [], "tested": [], "errors": []}

    headers = {"User-Agent": "DEDSEC-Recon/1.0"}
    vulnerable = []
    tested = []

    for param in REDIRECT_PARAMS:
        test_url = f"{url}?{param}={EVIL_URL}"
        tested.append(test_url)
        try:
            resp = requests.get(
                test_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )
            location = resp.headers.get("Location", "")
            # Parse the redirect location to check if it goes to evil.com (exact host match)
            from urllib.parse import urlparse as _urlparse
            loc_host = _urlparse(location).hostname or ""
            if location and (loc_host == "evil.com" or loc_host.endswith(".evil.com")):
                warn(f"VULNERABLE! Parameter '{param}' redirects to: {location}")
                vulnerable.append({"param": param, "url": test_url, "location": location})
            else:
                print(f"{Colors.DIM}[ ] {param}: {resp.status_code} — not vulnerable{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.DIM}[ ] {param}: error — {e}{Colors.RESET}")
            results["errors"].append({"param": param, "error": str(e)})

    if vulnerable:
        error(f"Found {len(vulnerable)} open redirect(s)!")
    else:
        info("Result", f"{Colors.GREEN}No open redirects detected (passive check){Colors.RESET}")

    results["vulnerable"] = vulnerable
    results["tested"] = tested
    results["total_tested"] = len(REDIRECT_PARAMS)
    return results
