import json
import requests
from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors


def run(url, domain, timeout=10):
    section("Subdomain Enumeration", "🌐")
    results = {"subdomains": [], "count": 0}

    # Use crt.sh (Certificate Transparency)
    api_url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(api_url, timeout=timeout)
        data = resp.json()
    except requests.exceptions.Timeout:
        error("crt.sh request timed out.")
        return results
    except json.JSONDecodeError:
        error("Failed to parse crt.sh response.")
        return results
    except Exception as e:
        error(f"crt.sh lookup failed: {e}")
        return {"error": str(e)}

    subdomains = set()
    for entry in data:
        names = entry.get("name_value", "")
        for name in names.splitlines():
            name = name.strip().lower()
            # Filter wildcards and root domain
            if name.startswith("*."):
                name = name[2:]
            if name == domain or name == f"www.{domain}":
                continue
            if name.endswith(f".{domain}") and name:
                subdomains.add(name)

    sorted_subs = sorted(subdomains)[:50]

    if sorted_subs:
        info("Unique Subdomains Found", str(len(subdomains)))
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Subdomains (showing up to 50):{Colors.RESET}")
        for sub in sorted_subs:
            print(f"       {Colors.CYAN}• {sub}{Colors.RESET}")
        if len(subdomains) > 50:
            warn(f"Showing 50 of {len(subdomains)} total subdomains.")
    else:
        warn("No subdomains found via certificate transparency.")

    results["subdomains"] = sorted_subs
    results["count"] = len(subdomains)
    results["source"] = "crt.sh (Certificate Transparency)"
    return results
