from urllib.parse import urljoin

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

POLICY_FILES = [
    ("/.well-known/security.txt", "security.txt"),
    ("/security.txt", "security.txt (root)"),
    ("/humans.txt", "humans.txt"),
    ("/ads.txt", "ads.txt"),
    ("/robots.txt", "robots.txt"),
]


def run(url, domain, timeout=10):
    section("Security Policy & Disclosure Audit", "📄")
    results = {"policies_found": [], "security_txt_valid": False, "issues": []}

    for path, label in POLICY_FILES:
        target = urljoin(url, path)
        resp = safe_request(target, timeout=timeout)
        if not resp or resp.status_code != 200:
            continue

        text = resp.text
        lower = text.lower()
        if (
            "contact:" in lower
            or "allow:" in lower
            or "disallow:" in lower
            or "google.com" in lower
            or "contact" in lower
        ):
            info("Found Policy File", f"{label} at {target}")
            results["policies_found"].append({"label": label, "url": target})

            if "security.txt" in path:
                if "contact:" in lower:
                    results["security_txt_valid"] = True
                    info("security.txt Contact", "Present")
                else:
                    warn("security.txt missing required 'Contact:' field!")
                    results["issues"].append("security.txt missing Contact field")

                if "expires:" in lower:
                    info("security.txt Expiration", "Policy expiry date declared")
                else:
                    warn("security.txt missing recommended 'Expires:' date field!")
                    results["issues"].append("security.txt missing Expires field")

    if not results["policies_found"]:
        info(
            "Policy Audit",
            f"{Colors.DIM}No policy disclosure files (.well-known/security.txt, etc.) found.{Colors.RESET}",
        )

    return results
