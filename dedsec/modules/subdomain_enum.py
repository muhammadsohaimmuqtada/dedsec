import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import get_wildcard_ips, info, is_wildcard_ip, safe_request, section, warn

MAX_CRT_RESULTS = 1000
MAX_DISPLAY = 200
_MAX_SUBDOMAIN_WORKERS = 30

# Common subdomain wordlist for DNS brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
    "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2",
    "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "api", "staging", "app", "secure", "portal",
    "cdn", "media", "assets", "images", "img", "download", "s3", "auth",
    "login", "sso", "id", "accounts", "dashboard", "panel", "manage",
    "management", "console", "monitor", "status", "health", "metrics", "logs",
    "git", "gitlab", "jira", "confluence", "wiki", "kb", "help", "develop",
    "development", "stage", "uat", "qa", "testing", "demo", "preview",
    "sandbox", "lab", "labs", "internal", "intranet", "remote", "citrix",
    "api2", "apiv2", "v1", "v2", "graphql", "rest", "ws", "gateway", "proxy",
    "lb", "mx1", "mx2", "relay", "outbound", "inbound", "backup", "db",
    "database", "redis", "cache", "search", "es", "elastic", "kibana",
    "jenkins", "ci", "build", "deploy", "k8s", "docker", "registry", "vault",
    "secret", "config", "reporting", "analytics", "tracking", "events",
    "webhook", "hooks", "notify", "notification", "push", "queue", "worker",
    "scheduler", "cron", "task", "jobs", "stream", "live", "video", "audio",
    "upload", "files", "storage", "bucket", "blob", "archive", "export",
    "import", "migrate", "legacy", "v3", "soap", "wsdl", "ews", "exchange",
    "owa", "webdav", "dav", "caldav", "carddav", "xmpp", "chat", "im",
    "meet", "conference", "collab", "share", "collaborate", "office", "erp",
    "crm", "hrm", "accounting", "finance", "billing", "payments", "pay",
    "checkout", "store", "marketplace", "catalog", "inventory", "warehouse",
    "logistics", "order", "orders", "cart", "pos", "feedback", "survey",
    "forms", "contact", "subscribe", "newsletter", "campaign", "promo",
    "coupon", "affiliate", "partner", "reseller", "agent", "broker",
    "smtp2", "pop3s", "imaps", "smtps", "ns4", "ns5", "dns", "dns1", "dns2",
    "fw", "firewall", "dmz", "router", "switch", "ntp", "ldap", "ldaps",
    "radius", "tacacs", "siem", "ids", "ips", "waf", "proxy1", "proxy2",
    "haproxy", "nginx", "apache", "tomcat", "jboss", "iis",
]

# Cloud Subdomain Takeover Signatures
TAKEOVER_SIGNATURES = [
    ("AWS S3", ".s3.amazonaws.com", "the specified bucket does not exist"),
    ("GitHub Pages", "github.io", "there isn't a github pages site here"),
    ("Heroku", "herokudns.com", "no such app"),
    ("Shopify", "myshopify.com", "sorry, this shop is currently unavailable"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Ghost", "ghost.io", "the thing you were looking for is no longer here"),
    ("Pantheon", "pantheonsite.io", "the site you were looking for could not be found"),
]


def _resolve(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except Exception:
        return None


def _probe_alive(subdomain, timeout):
    for scheme in ("https", "http"):
        target = f"{scheme}://{subdomain}"
        resp = safe_request(target, timeout=timeout, allow_redirects=False)
        if resp and resp.status_code < 500:
            return {"url": target, "status": resp.status_code}
    return None


def _check_subdomain_takeover(subdomain, url, timeout):
    resp = safe_request(url, timeout=timeout)
    if not resp:
        return None
    body_lower = resp.text.lower()
    for provider, cname_marker, body_fingerprint in TAKEOVER_SIGNATURES:
        if body_fingerprint in body_lower:
            return {"provider": provider, "fingerprint": body_fingerprint, "url": url}
    return None


def _fetch_crtsh(domain, timeout):
    """Query crt.sh Certificate Transparency logs."""
    found = set()
    api_url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = safe_request(api_url, timeout=timeout)
    if not resp:
        return found, 0
    try:
        data = resp.json()
    except (json.JSONDecodeError, Exception):
        return found, 0

    for entry in data[:MAX_CRT_RESULTS]:
        names = entry.get("name_value", "")
        for name in names.splitlines():
            candidate = name.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if candidate.endswith(f".{domain}") and candidate not in {domain, f"www.{domain}"}:
                found.add(candidate)
    return found, len(found)


def _fetch_certspotter(domain, timeout):
    """Query CertSpotter API for CT log entries."""
    found = set()
    api_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    resp = safe_request(api_url, timeout=timeout)
    if not resp or resp.status_code != 200:
        return found
    try:
        data = resp.json()
    except Exception:
        return found
    for entry in data:
        for name in entry.get("dns_names", []):
            candidate = name.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if candidate.endswith(f".{domain}") and candidate not in {domain, f"www.{domain}"}:
                found.add(candidate)
    return found


def _fetch_hackertarget(domain, timeout):
    """Query HackerTarget hostsearch API."""
    found = set()
    api_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = safe_request(api_url, timeout=timeout)
    if not resp or resp.status_code != 200:
        return found
    for line in resp.text.splitlines():
        parts = line.strip().split(",")
        if len(parts) >= 1:
            candidate = parts[0].strip().lower()
            if candidate.endswith(f".{domain}") and candidate not in {domain, f"www.{domain}"}:
                found.add(candidate)
    return found


def _reverse_ip_lookup(ip, timeout):
    """Query HackerTarget reverse-IP lookup for co-hosted domains."""
    found = set()
    api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    resp = safe_request(api_url, timeout=timeout)
    if resp and resp.status_code == 200 and "No records found" not in resp.text:
        for line in resp.text.splitlines():
            candidate = line.strip().lower()
            if candidate:
                found.add(candidate)
    return found


def _bruteforce_subdomains(domain, timeout):
    """Try resolving common subdomain prefixes."""
    found = set()

    def _try(word):
        candidate = f"{word}.{domain}"
        if _resolve(candidate):
            return candidate
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_try, word): word for word in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
    return found


def _generate_permutations(domain):
    """Generate common permutation subdomains based on domain label."""
    parts = domain.split(".")
    label = parts[0] if parts else domain
    perms = set()
    affixes = ["dev", "staging", "test", "prod", "api", "old", "new", "beta",
               "stage", "uat", "preview", "demo", "sandbox", "internal"]
    for affix in affixes:
        perms.add(f"{affix}.{domain}")
        perms.add(f"{affix}-{label}.{domain.split('.', 1)[1] if '.' in domain else domain}")
        perms.add(f"{label}-{affix}.{domain.split('.', 1)[1] if '.' in domain else domain}")
    return {p for p in perms if p.endswith(f".{domain}") or p != domain}


def run(url, domain, timeout=10):
    section("Subdomain Enumeration", "🌐")
    results = {
        "sources": {},
        "discovered_count": 0,
        "resolved_count": 0,
        "alive_count": 0,
        "resolved": [],
        "alive": [],
        "takeovers": [],
        "wildcard_ips": [],
    }

    # Obtain Wildcard DNS IPs for domain
    wildcard_ips = get_wildcard_ips(domain)
    if wildcard_ips:
        info("Wildcard DNS IPs Detected", ", ".join(wildcard_ips))
        results["wildcard_ips"] = list(wildcard_ips)

    # --- Source 1: crt.sh ---
    crt_found, crt_raw = _fetch_crtsh(domain, timeout)
    results["sources"]["crt.sh"] = len(crt_found)

    # --- Source 2: CertSpotter ---
    cs_found = _fetch_certspotter(domain, timeout)
    results["sources"]["certspotter"] = len(cs_found)

    # --- Source 3: HackerTarget hostsearch ---
    ht_found = _fetch_hackertarget(domain, timeout)
    results["sources"]["hackertarget"] = len(ht_found)

    # --- Source 4: Permutations ---
    perm_found = _generate_permutations(domain)
    perm_resolved = {p for p in perm_found if _resolve(p)}
    results["sources"]["permutations"] = len(perm_resolved)

    # --- Source 5: DNS brute-force ---
    bf_found = _bruteforce_subdomains(domain, timeout)
    results["sources"]["bruteforce"] = len(bf_found)

    # Merge all discovered subdomains
    discovered = crt_found | cs_found | ht_found | perm_resolved | bf_found

    # --- Source 6: Reverse-IP lookup on resolved IPs ---
    sample_ips = set()
    for sub in list(discovered)[:20]:
        ip = _resolve(sub)
        if ip and not is_wildcard_ip(ip, wildcard_ips):
            sample_ips.add(ip)

    reverse_found = set()
    if sample_ips:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(_reverse_ip_lookup, ip, timeout): ip for ip in list(sample_ips)[:5]}
            for future in as_completed(futures):
                reverse_found.update(future.result())

    # Filter reverse-IP results to same domain
    reverse_domain_matches = {
        h for h in reverse_found
        if h.endswith(f".{domain}") and h not in {domain, f"www.{domain}"}
    }
    discovered.update(reverse_domain_matches)
    results["sources"]["reverse_ip"] = len(reverse_domain_matches)

    results["discovered_count"] = len(discovered)
    if not discovered:
        warn("No subdomains found from any source.")
        return results

    # Print source breakdown
    print(f"\n{Colors.BOLD}  Sources:{Colors.RESET}")
    for src, count in results["sources"].items():
        color = Colors.GREEN if count > 0 else Colors.DIM
        print(f"    {color}\u2022 {src}: {count}{Colors.RESET}")
    info("Total Unique Discovered", str(len(discovered)))

    # --- Resolve + Probe Alive ---
    resolved = []
    alive = []

    def _resolve_and_probe(subdomain):
        ip = _resolve(subdomain)
        if not ip or is_wildcard_ip(ip, wildcard_ips):
            return None
        probe = _probe_alive(subdomain, timeout)
        return subdomain, ip, probe

    with ThreadPoolExecutor(max_workers=_MAX_SUBDOMAIN_WORKERS) as executor:
        futures = {
            executor.submit(_resolve_and_probe, subdomain): subdomain
            for subdomain in sorted(discovered)
        }
        for future in as_completed(futures):
            result_item = future.result()
            if result_item is None:
                continue
            subdomain, ip, probe = result_item
            resolved.append({"subdomain": subdomain, "ip": ip})
            if probe:
                alive.append({
                    "subdomain": subdomain,
                    "ip": ip,
                    "url": probe["url"],
                    "status": probe["status"],
                })

    results["resolved_count"] = len(resolved)
    results["alive_count"] = len(alive)
    results["resolved"] = resolved[:MAX_DISPLAY]
    results["alive"] = alive[:MAX_DISPLAY]

    info("Resolved", str(len(resolved)))
    info("Alive Web Hosts", str(len(alive)))

    if alive:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Validated subdomains (showing up to {MAX_DISPLAY}):{Colors.RESET}")
        for item in alive[:MAX_DISPLAY]:
            print(f"       {Colors.CYAN}\u2022 {item['subdomain']} -> {item['ip']} ({item['status']}){Colors.RESET}")
        if len(alive) > MAX_DISPLAY:
            warn(f"Showing {MAX_DISPLAY} of {len(alive)} alive subdomains.")

        # --- Cloud Takeover Check on Alive Subdomains ---
        takeovers = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_check_subdomain_takeover, item["subdomain"], item["url"], timeout): item
                for item in alive[:30]
            }
            for future in as_completed(futures):
                to_res = future.result()
                if to_res:
                    takeovers.append(to_res)

        if takeovers:
            print(f"\n{Colors.RED}[!]{Colors.RESET} {Colors.BOLD}Subdomain Takeovers Detected:{Colors.RESET}")
            for to in takeovers:
                warn(f"HIGH: {to['url']} vulnerable to {to['provider']} takeover! ('{to['fingerprint']}')")
            results["takeovers"] = takeovers

    else:
        warn("No live web subdomains validated.")

    return results
