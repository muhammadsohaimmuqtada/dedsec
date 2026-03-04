from urllib.parse import urljoin
from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap/",
    "/wp-sitemap.xml",
]


def run(url, domain, timeout=10):
    section("Robots & Sitemap", "🤖")
    results = {"robots": {}, "sitemaps": {}}

    base = f"{url.rstrip('/')}"

    # Robots.txt
    robots_url = urljoin(base + "/", "robots.txt")
    resp = safe_request(robots_url, timeout=timeout)
    if resp and resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
        info("robots.txt", "Found")
        lines = resp.text.splitlines()
        disallowed = []
        sitemaps_from_robots = []
        current_agent = "*"

        for line in lines:
            line = line.strip()
            if line.lower().startswith("user-agent:"):
                current_agent = line.split(":", 1)[1].strip()
            elif line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
                # Use split with maxsplit=1 then re-join to preserve URL scheme (e.g., https://)
                sm = line[len("sitemap:"):].strip()
                sitemaps_from_robots.append(sm)

        if disallowed:
            print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Disallowed Paths ({len(disallowed)}):{Colors.RESET}")
            for path in disallowed[:30]:
                print(f"       {Colors.YELLOW}• {path}{Colors.RESET}")
            if len(disallowed) > 30:
                print(f"       {Colors.DIM}... and {len(disallowed)-30} more{Colors.RESET}")
        else:
            print(f"{Colors.DIM}[ ] No Disallow entries found{Colors.RESET}")

        if sitemaps_from_robots:
            info("Sitemaps in robots.txt", ", ".join(sitemaps_from_robots))

        results["robots"] = {
            "url": robots_url,
            "disallowed": disallowed,
            "sitemaps": sitemaps_from_robots,
        }
    else:
        warn("robots.txt not found or inaccessible.")
        results["robots"] = {"url": robots_url, "status": "not found"}

    # Sitemap probing
    print(f"\n{Colors.BOLD}  Probing Sitemap Locations:{Colors.RESET}")
    found_sitemaps = {}
    for path in SITEMAP_PATHS:
        sm_url = urljoin(base + "/", path.lstrip("/"))
        r = safe_request(sm_url, timeout=timeout)
        if r and r.status_code == 200:
            size = len(r.content)
            print(f"  {Colors.GREEN}✔{Colors.RESET}  {sm_url} — {size} bytes")
            # Count URLs in sitemap
            url_count = r.text.count("<url>") + r.text.count("<sitemap>")
            found_sitemaps[sm_url] = {"size": size, "entries": url_count}
        else:
            status = r.status_code if r else "error"
            print(f"  {Colors.DIM}✘  {sm_url} — {status}{Colors.RESET}")

    results["sitemaps"] = found_sitemaps
    return results
