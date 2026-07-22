import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dedsec.core.colors import Colors
from dedsec.core.utils import section, info, warn, error

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "s1", "s2",
    "mailjet", "sendgrid", "amazonses", "key1", "smtp"
]

def _resolve_txt(domain, selector=None):
    if not _DNS_AVAILABLE:
        return []
    target = f"{selector}._domainkey.{domain}" if selector else domain
    try:
        answers = dns.resolver.resolve(target, "TXT")
        return [str(rdata).strip().replace('"', "") for rdata in answers]
    except Exception:
        return []

def _check_open_relay(mx_host):
    """
    Safely probe for open relay configuration on MX host.
    Sends standard EHLO, MAIL FROM, RCPT TO sequence, stops without relaying.
    """
    try:
        sock = socket.create_connection((mx_host, 25), timeout=5)
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        
        # SMTP handshake
        sock.send(b"EHLO dedsec.recon\r\n")
        resp1 = sock.recv(1024).decode()
        
        # Mail from external attacker
        sock.send(b"MAIL FROM:<test@evil.example.com>\r\n")
        resp2 = sock.recv(1024).decode()
        
        # RCPT to external destination
        sock.send(b"RCPT TO:<external_test@gmail.com>\r\n")
        resp3 = sock.recv(1024).decode()
        
        sock.send(b"QUIT\r\n")
        sock.close()
        
        is_relay = "250" in resp3 or "251" in resp3
        return banner, is_relay
    except Exception:
        return None, False

def run(url, domain, timeout=10):
    section("Email Security Audit", "✉️")
    results = {"spf": {}, "dmarc": {}, "dkim": {}, "mx": [], "score": 100, "risks": []}

    if not _DNS_AVAILABLE:
        error("dnspython package is not installed. Skipping email security audit.")
        return results

    # 1. SPF Check
    spf_recs = _resolve_txt(domain)
    spf_record = next((r for r in spf_recs if r.lower().startswith("v=spf1")), None)
    results["spf"]["record"] = spf_record
    
    if not spf_record:
        warn("SPF record is missing! Anyone can spoof emails from this domain.")
        results["risks"].append("Missing SPF record")
        results["score"] -= 30
    else:
        spf_lower = spf_record.lower()
        if "+all" in spf_lower:
            error("SPF policy allows '+all' (anyone can send email as this domain)!")
            results["risks"].append("SPF policy allows +all (CRITICAL)")
            results["score"] -= 40
        elif "?all" in spf_lower:
            warn("SPF policy is '?all' (neutral/permissive).")
            results["risks"].append("Weak SPF policy (?all)")
            results["score"] -= 15
        elif "~all" in spf_lower:
            warn("SPF policy is '~all' (softfail). Better than nothing, but not strict.")
            results["risks"].append("Weak SPF policy (~all)")
            results["score"] -= 5
        elif "-all" in spf_lower:
            info("SPF", f"{Colors.GREEN}Strict SPF policy in use (-all){Colors.RESET}")

    # 2. DMARC Check
    dmarc_recs = _resolve_txt(f"_dmarc.{domain}")
    dmarc_record = next((r for r in dmarc_recs if r.lower().startswith("v=dmarc1")), None)
    results["dmarc"]["record"] = dmarc_record

    if not dmarc_record:
        warn("DMARC record is missing!")
        results["risks"].append("Missing DMARC record")
        results["score"] -= 25
    else:
        dmarc_lower = dmarc_record.lower()
        if "p=none" in dmarc_lower:
            warn("DMARC policy is 'p=none' (only monitoring, no enforcement).")
            results["risks"].append("Weak DMARC policy (p=none)")
            results["score"] -= 10
        elif "p=quarantine" in dmarc_lower:
            info("DMARC", f"{Colors.GREEN}Enforced DMARC policy (p=quarantine){Colors.RESET}")
        elif "p=reject" in dmarc_lower:
            info("DMARC", f"{Colors.GREEN}Enforced DMARC policy (p=reject){Colors.RESET}")

    # 3. DKIM Check
    dkim_found = []
    def _test_selector(sel):
        recs = _resolve_txt(domain, sel)
        for r in recs:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                return sel
        return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_test_selector, sel): sel for sel in DKIM_SELECTORS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                dkim_found.append(res)
    
    results["dkim"]["selectors"] = dkim_found
    if dkim_found:
        info("DKIM", f"{Colors.GREEN}DKIM key found on selector(s): {', '.join(dkim_found)}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[ ] No DKIM keys found on common selectors (informational){Colors.RESET}")

    # 4. MX and SMTP Open Relay Check
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_servers = sorted([str(rdata.exchange).rstrip(".") for rdata in answers])
    except Exception:
        mx_servers = []

    results["mx"] = mx_servers
    if mx_servers:
        info("MX Servers", ", ".join(mx_servers))
        print("  Probing MX servers for open relay and banner leaks...")
        for mx in mx_servers[:3]:
            banner, is_relay = _check_open_relay(mx)
            entry = {"mx": mx, "banner": banner, "open_relay": is_relay}
            if banner:
                print(f"       {Colors.DIM}MX Banner ({mx}): {banner}{Colors.RESET}")
            if is_relay:
                error(f"CRITICAL: MX Server '{mx}' configured as OPEN RELAY!")
                results["risks"].append(f"Open relay on {mx}")
                results["score"] -= 50
    else:
        warn("No MX records found for the domain.")

    results["score"] = max(results["score"], 0)
    color = Colors.GREEN if results["score"] >= 80 else Colors.YELLOW if results["score"] >= 50 else Colors.RED
    info("Email Security Score", f"{color}{results['score']}/100{Colors.RESET}")

    return results
