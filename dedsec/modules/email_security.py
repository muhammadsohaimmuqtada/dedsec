from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, section, warn

try:
    import dns.resolver

    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "s1", "s2",
    "mailjet", "sendgrid", "amazonses", "key1", "smtp",
]


def _resolve_txt(domain, selector=None, timeout=5):
    if not _DNS_AVAILABLE:
        return []
    target = f"{selector}._domainkey.{domain}" if selector else domain
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = min(timeout, 4)
        resolver.lifetime = min(timeout, 6)
        answers = resolver.resolve(target, "TXT", raise_on_no_answer=False)
        if not answers:
            return []
        return [str(rdata).strip().replace('"', "") for rdata in answers]
    except Exception:
        return []


def run(url, domain, timeout=10):
    section("Email Security Audit", "✉️")
    results = {
        "spf": {},
        "dmarc": {},
        "dkim": {},
        "mx": [],
        "score": 100,
        "score_metric": "email-authentication-posture",
        "risks": [],
        "observations": [],
        "smtp_probe_performed": False,
    }

    if not _DNS_AVAILABLE:
        error("dnspython package is not installed. Skipping email security audit.")
        return {"error": "dnspython not installed"}

    spf_recs = _resolve_txt(domain, timeout=timeout)
    spf_record = next((record for record in spf_recs if record.lower().startswith("v=spf1")), None)
    results["spf"]["record"] = spf_record
    if not spf_record:
        warn("SPF record not present (email-authentication posture observation).")
        results["observations"].append("SPF record not present")
        results["score"] -= 20
    else:
        lower = spf_record.lower()
        if "+all" in lower:
            results["risks"].append("SPF policy allows +all")
            results["score"] -= 40
            error("SPF policy contains '+all', authorizing all senders.")
        elif "?all" in lower:
            results["risks"].append("SPF neutral policy (?all)")
            results["score"] -= 15
            warn("SPF policy uses '?all' (neutral).")
        elif "~all" in lower:
            results["observations"].append("SPF softfail policy (~all)")
            results["score"] -= 5
            warn("SPF policy uses '~all' (softfail).")
        elif "-all" in lower:
            info("SPF", f"{Colors.GREEN}Strict SPF policy detected (-all){Colors.RESET}")

    dmarc_recs = _resolve_txt(f"_dmarc.{domain}", timeout=timeout)
    dmarc_record = next((record for record in dmarc_recs if record.lower().startswith("v=dmarc1")), None)
    results["dmarc"]["record"] = dmarc_record
    if not dmarc_record:
        warn("DMARC record not present (email-authentication posture observation).")
        results["observations"].append("DMARC record not present")
        results["score"] -= 20
    else:
        lower = dmarc_record.lower()
        if "p=none" in lower:
            results["observations"].append("DMARC monitoring-only policy (p=none)")
            results["score"] -= 10
            warn("DMARC policy is p=none (monitoring only).")
        elif "p=quarantine" in lower:
            info("DMARC", f"{Colors.GREEN}Enforced policy p=quarantine{Colors.RESET}")
        elif "p=reject" in lower:
            info("DMARC", f"{Colors.GREEN}Enforced policy p=reject{Colors.RESET}")

    def _test_selector(selector):
        recs = _resolve_txt(domain, selector, timeout=timeout)
        if any("v=dkim1" in record.lower() or "p=" in record.lower() for record in recs):
            return selector
        return None

    dkim_found = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_test_selector, selector) for selector in DKIM_SELECTORS]
        for future in as_completed(futures):
            selector = future.result()
            if selector:
                dkim_found.append(selector)
    results["dkim"] = {
        "selectors": sorted(dkim_found),
        "tested_selectors": list(DKIM_SELECTORS),
        "complete": False,
    }
    if dkim_found:
        info("DKIM", f"Found on tested selector(s): {', '.join(sorted(dkim_found))}")
    else:
        print(
            f"  {Colors.DIM}[ ] No DKIM keys discovered on tested common selectors; absence is not proven.{Colors.RESET}"
        )

    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = min(timeout, 4)
        resolver.lifetime = min(timeout, 6)
        answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
        mx_servers = sorted(str(rdata.exchange).rstrip(".") for rdata in answers) if answers else []
    except Exception:
        mx_servers = []
    results["mx"] = mx_servers
    if mx_servers:
        info("MX Servers", ", ".join(mx_servers))
        print(
            f"  {Colors.DIM}[ ] SMTP relay probing is intentionally not performed by the default email audit.{Colors.RESET}"
        )
    else:
        print(f"  {Colors.DIM}[ ] No MX records observed for the domain.{Colors.RESET}")

    results["score"] = max(results["score"], 0)
    info(
        "Email Authentication Posture",
        f"{results['score']}/100 (configuration coverage metric, not a vulnerability score)",
    )
    return results
