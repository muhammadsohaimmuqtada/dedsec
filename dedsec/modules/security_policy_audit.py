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


def _non_comment_lines(text):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _looks_like_policy(path, text):
    lines = _non_comment_lines(text)
    if not lines:
        return False

    lower_lines = [line.lower() for line in lines]
    if "security.txt" in path:
        return any(line.startswith("contact:") for line in lower_lines)

    if path.endswith("robots.txt"):
        prefixes = ("user-agent:", "allow:", "disallow:", "sitemap:")
        return any(line.startswith(prefixes) for line in lower_lines)

    if path.endswith("ads.txt"):
        for line in lines:
            fields = [field.strip() for field in line.split(",")]
            if len(fields) >= 3 and fields[2].upper() in {"DIRECT", "RESELLER"}:
                return True
        return False

    if path.endswith("humans.txt"):
        if any("<html" in line or "<!doctype" in line for line in lower_lines):
            return False
        prefixes = ("team:", "site:", "thanks:", "contact:", "technology:")
        return any(line.startswith(prefixes) for line in lower_lines)

    return False


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
        if not _looks_like_policy(path, text):
            continue

        info("Found Policy File", f"{label} at {target}")
        results["policies_found"].append({"label": label, "url": target})

        if "security.txt" in path:
            results["security_txt_valid"] = True
            info("security.txt Contact", "Present")

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
