import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import get_wildcard_ips, info, is_wildcard_ip, safe_request, section, warn

MAX_CRT_RESULTS = 1000
MAX_DISPLAY = 200
_MAX_SUBDOMAIN_WORKERS = 24

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
        resp = safe_request(target, timeout=timeout, allow_redirects=False, cache=False)
        if resp is not None and resp.status_code < 500:
            return {"url": target, "status": resp.status_code}
    return None


def _check_subdomain_takeover(url, timeout):
    resp = safe_request(url, timeout=timeout, cache=False)
    if resp is None:
        return None
    body_lower = resp.text.lower()
    for provider, cname_marker, body_fingerprint in TAKEOVER_SIGNATURES:
        if body_fingerprint in body_lower:
            return {
                "provider": provider,
                "fingerprint": body_fingerprint,
                "url": url,
                "verified": False,
                "proof": None,
                "classification": "provider-fingerprint-candidate",
            }
    return None


def _fetch_crtsh(domain, timeout):
    found = set()
    api_url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = safe_request(api_url, timeout=timeout, cache=False)
    if resp is None:
        return found
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return found
    for entry in data[:MAX_CRT_RESULTS]:
        for name in entry.get("name_value", "").splitlines():
            candidate = name.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if candidate.endswith(f".{domain}") and candidate != domain:
                found.add(candidate)
    return found


def _fetch_certspotter(domain, timeout):
    found = set()
    api_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    resp = safe_request(api_url, timeout=timeout, cache=False)
    if resp is None or resp.status_code != 200:
        return found
    try:
        data = resp.json()
    except ValueError:
        return found
    for entry in data:
        for name in entry.get("dns_names", []):
            candidate = name.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            if candidate.endswith(f".{domain}") and candidate != domain:
                found.add(candidate)
    return found


def _fetch_hackertarget(domain, timeout):
    found = set()
    api_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = safe_request(api_url, timeout=timeout, cache=False)
    if resp is None or resp.status_code != 200:
        return found
    for line in resp.text.splitlines():
        candidate = line.strip().split(",", 1)[0].lower()
        if candidate.endswith(f".{domain}") and candidate != domain:
            found.add(candidate)
    return found


def _reverse_ip_lookup(ip, timeout):
    found = set()
    api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    resp = safe_request(api_url, timeout=timeout, cache=False)
    if resp is not None and resp.status_code == 200 and "No records found" not in resp.text:
        for line in resp.text.splitlines():
            candidate = line.strip().lower()
            if candidate:
                found.add(candidate)
    return found


def _bruteforce_subdomains(domain):
    found = set()

    def _try(word):
        candidate = f"{word}.{domain}"
        return candidate if _resolve(candidate) else None

    with ThreadPoolExecutor(max_workers=24) as executor:
        futures = {executor.submit(_try, word): word for word in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
    return found


def _generate_permutations(domain):
    parts = domain.split(".")
    label = parts[0] if parts else domain
    suffix = domain.split(".", 1)[1] if "." in domain else domain
    perms = set()
    for affix in ["dev", "staging", "test", "prod", "api", "old", "new", "beta", "stage", "uat", "preview", "demo", "sandbox", "internal"]:
        perms.add(f"{affix}.{domain}")
        perms.add(f"{affix}-{label}.{suffix}")
        perms.add(f"{label}-{affix}.{suffix}")
    return {item for item in perms if item.endswith(f".{domain}")}


def run(url, domain, timeout=10):
    section("Subdomain Enumeration", "🌐")
    results = {
        "sources": {},
        "discovered_count": 0,
        "resolved_count": 0,
        "alive_count": 0,
        "discovered": [],
        "unresolved": [],
        "resolved": [],
        "alive": [],
        "takeovers": [],
        "wildcard_ips": [],
    }

    wildcard_ips = get_wildcard_ips(domain)
    if wildcard_ips:
        info("Wildcard DNS IPs Detected", ", ".join(sorted(wildcard_ips)))
        results["wildcard_ips"] = sorted(wildcard_ips)

    source_sets = {
        "crt.sh": _fetch_crtsh(domain, timeout),
        "certspotter": _fetch_certspotter(domain, timeout),
        "hackertarget": _fetch_hackertarget(domain, timeout),
    }
    permutations = _generate_permutations(domain)
    source_sets["permutations"] = {item for item in permutations if _resolve(item)}
    source_sets["bruteforce"] = _bruteforce_subdomains(domain)

    discovered = set().union(*source_sets.values())
    sample_ips = {
        ip for ip in (_resolve(sub) for sub in list(discovered)[:20])
        if ip and not is_wildcard_ip(ip, wildcard_ips)
    }
    reverse_found = set()
    if sample_ips:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(_reverse_ip_lookup, ip, timeout): ip for ip in list(sample_ips)[:5]}
            for future in as_completed(futures):
                reverse_found.update(future.result())
    source_sets["reverse_ip"] = {
        host for host in reverse_found if host.endswith(f".{domain}") and host != domain
    }
    discovered.update(source_sets["reverse_ip"])

    results["sources"] = {name: len(values) for name, values in source_sets.items()}
    results["discovered_count"] = len(discovered)
    if not discovered:
        warn("No subdomains found from any source.")
        return results

    print(f"\n{Colors.BOLD}  Sources:{Colors.RESET}")
    for source, count in results["sources"].items():
        color = Colors.GREEN if count else Colors.DIM
        print(f"    {color}• {source}: {count}{Colors.RESET}")
    info("Total Unique Discovered", str(len(discovered)))

    provenance = {
        host: sorted(source for source, values in source_sets.items() if host in values)
        for host in discovered
    }
    resolved = []
    unresolved = []
    alive = []

    def _resolve_and_probe(subdomain):
        ip = _resolve(subdomain)
        if not ip:
            return subdomain, None, None, "unresolved"
        if is_wildcard_ip(ip, wildcard_ips):
            return subdomain, ip, None, "wildcard"
        return subdomain, ip, _probe_alive(subdomain, timeout), "resolved"

    with ThreadPoolExecutor(max_workers=_MAX_SUBDOMAIN_WORKERS) as executor:
        futures = {executor.submit(_resolve_and_probe, sub): sub for sub in sorted(discovered)}
        for future in as_completed(futures):
            subdomain, ip, probe, state = future.result()
            record = {"subdomain": subdomain, "sources": provenance.get(subdomain, []), "state": state}
            if ip:
                record["ip"] = ip
            if state in {"unresolved", "wildcard"}:
                unresolved.append(record)
                continue
            resolved.append({"subdomain": subdomain, "ip": ip, "sources": record["sources"]})
            if probe:
                alive.append(
                    {
                        "subdomain": subdomain,
                        "ip": ip,
                        "url": probe["url"],
                        "status": probe["status"],
                        "sources": record["sources"],
                    }
                )

    discovered_records = []
    resolved_by_name = {item["subdomain"]: item for item in resolved}
    unresolved_by_name = {item["subdomain"]: item for item in unresolved}
    alive_by_name = {item["subdomain"]: item for item in alive}
    for subdomain in sorted(discovered):
        record = {
            "subdomain": subdomain,
            "sources": provenance.get(subdomain, []),
            "resolved": subdomain in resolved_by_name,
            "alive": subdomain in alive_by_name,
        }
        if subdomain in resolved_by_name:
            record["ip"] = resolved_by_name[subdomain]["ip"]
        if subdomain in unresolved_by_name:
            record["resolution_state"] = unresolved_by_name[subdomain]["state"]
        discovered_records.append(record)

    results["discovered"] = discovered_records[:MAX_DISPLAY]
    results["unresolved"] = sorted(unresolved, key=lambda item: item["subdomain"])[:MAX_DISPLAY]
    results["resolved"] = sorted(resolved, key=lambda item: item["subdomain"])[:MAX_DISPLAY]
    results["alive"] = sorted(alive, key=lambda item: item["subdomain"])[:MAX_DISPLAY]
    results["resolved_count"] = len(resolved)
    results["alive_count"] = len(alive)

    info("Resolved", str(len(resolved)))
    info("Alive Web Hosts", str(len(alive)))
    if unresolved:
        info("Unresolved/Wildcard Candidates Preserved", str(len(unresolved)))

    if alive:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Validated subdomains (showing up to {MAX_DISPLAY}):{Colors.RESET}")
        for item in sorted(alive, key=lambda entry: entry["subdomain"])[:MAX_DISPLAY]:
            print(f"       {Colors.CYAN}• {item['subdomain']} -> {item['ip']} ({item['status']}){Colors.RESET}")

        takeovers = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(_check_subdomain_takeover, item["url"], timeout): item
                for item in alive[:30]
            }
            for future in as_completed(futures):
                candidate = future.result()
                if candidate:
                    takeovers.append(candidate)
        if takeovers:
            print(f"\n{Colors.YELLOW}[!]{Colors.RESET} {Colors.BOLD}Takeover Fingerprint Candidates:{Colors.RESET}")
            for item in takeovers:
                warn(
                    f"Candidate: {item['url']} matches {item['provider']} error fingerprint; claimability is NOT verified."
                )
            results["takeovers"] = takeovers
    else:
        warn("No live web subdomains validated.")

    return results
