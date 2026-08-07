import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from dedsec.core.colors import Colors
from dedsec.core.utils import (
    get_soft404_profile,
    info,
    is_soft_404,
    safe_request,
    section,
    warn,
)

SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap/",
    "/wp-sitemap.xml",
]
SITEMAP_ROOTS = {"urlset": "url", "sitemapindex": "sitemap"}


def _local_name(tag):
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def _sitemap_document_summary(response):
    """Return structural sitemap metadata, or ``None`` for non-sitemap bodies.

    HTTP 200 alone is not sitemap evidence. Many SPAs and custom 404 handlers
    return the application shell for arbitrary paths, so the response must be a
    well-formed XML document whose root is either ``urlset`` or
    ``sitemapindex``. Namespaced sitemap documents are supported.
    """
    if response is None:
        return None
    text = getattr(response, "text", "") or ""
    if not text.strip():
        return None
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, TypeError):
        return None

    root_name = _local_name(root.tag)
    entry_name = SITEMAP_ROOTS.get(root_name)
    if entry_name is None:
        return None

    entries = sum(1 for element in root.iter() if _local_name(element.tag) == entry_name)
    content = getattr(response, "content", None)
    size = len(content) if content is not None else len(text.encode("utf-8", errors="replace"))
    return {"size": size, "entries": entries, "type": root_name}


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

        for line in lines:
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
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

    # Sitemap probing. Build one bounded soft-404 profile so application-shell
    # fallbacks cannot be promoted to sitemap evidence merely because they are 200.
    soft404_profile = get_soft404_profile(base, timeout=min(timeout, 8))
    print(f"\n{Colors.BOLD}  Probing Sitemap Locations:{Colors.RESET}")
    found_sitemaps = {}
    for path in SITEMAP_PATHS:
        sm_url = urljoin(base + "/", path.lstrip("/"))
        r = safe_request(sm_url, timeout=timeout)
        if not r or r.status_code != 200:
            status = r.status_code if r else "error"
            print(f"  {Colors.DIM}✘  {sm_url} — {status}{Colors.RESET}")
            continue

        if is_soft_404(r, soft404_profile):
            print(f"  {Colors.DIM}✘  {sm_url} — soft-404 response match{Colors.RESET}")
            continue

        summary = _sitemap_document_summary(r)
        if summary is None:
            print(f"  {Colors.DIM}✘  {sm_url} — non-sitemap response body{Colors.RESET}")
            continue

        print(
            f"  {Colors.GREEN}✔{Colors.RESET}  {sm_url} — "
            f"{summary['size']} bytes, {summary['entries']} entries"
        )
        found_sitemaps[sm_url] = summary

    results["sitemaps"] = found_sitemaps
    return results
