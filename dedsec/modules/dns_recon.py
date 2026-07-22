import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, section, warn

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
MAX_RECORDS_PER_TYPE = 25

try:
    import dns.exception
    import dns.query
    import dns.resolver
    import dns.zone

    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


def _fetch_record(resolver, domain, rtype):
    """Query a single DNS record type; returns (rtype, values, error_code)."""
    try:
        values = _resolve_records(resolver, domain, rtype)
        return rtype, values, None
    except dns.resolver.NXDOMAIN:
        return rtype, [], "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return rtype, [], f"{rtype} query failed: authoritative nameserver unavailable"
    except dns.exception.Timeout:
        return rtype, [], f"{rtype} query timed out."
    except Exception as exc:
        return rtype, [], f"{rtype} query failed: {exc}"


def _resolver(timeout):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(timeout, 4)
    resolver.lifetime = timeout
    return resolver


def _resolve_records(resolver, domain, rtype):
    answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
    if not answers:
        return []
    values = [str(rdata).strip() for rdata in answers][:MAX_RECORDS_PER_TYPE]
    return values


def _extract_txt_like(values):
    normalized = []
    for value in values:
        normalized.append(value.strip('"').replace('" "', ""))
    return normalized


DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "s1", "s2",
    "mailjet", "sendgrid", "amazonses", "selector1", "selector2",
    "smtp", "email", "key1", "key2",
]


def _check_dkim(domain, timeout):
    """Check common DKIM selectors. Returns list of found selectors."""
    found = []
    resolver = _resolver(timeout)

    def _try_selector(sel):
        try:
            recs = _resolve_records(resolver, f"{sel}._domainkey.{domain}", "TXT")
            for rec in recs:
                if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                    return sel
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_try_selector, sel): sel for sel in DKIM_SELECTORS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return found


def _check_dnssec(domain, timeout):
    """Check if DS records exist (DNSSEC enabled at parent)."""
    try:
        resolver = _resolver(timeout)
        ds_records = _resolve_records(resolver, domain, "DS")
        return bool(ds_records), ds_records
    except Exception:
        return False, []


def _check_dangling_cnames(domain, cname_records, timeout):
    """For each CNAME target, try to resolve it. Unresolvable = potential takeover."""
    dangling = []
    for cname_target in cname_records:
        target = cname_target.rstrip(".")
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            # NXDOMAIN / unresolvable CNAME target
            dangling.append({"cname": domain, "target": target})
        except Exception:
            pass
    return dangling


def _security_posture(domain, txt_records):
    findings = {
        "spf": {"present": False, "strict": False, "policy": None, "severity": None},
        "dmarc": {"present": False, "strict": False, "policy": None},
    }

    spf_values = [txt for txt in txt_records if txt.lower().startswith("v=spf1")]
    findings["spf"]["present"] = bool(spf_values)
    if spf_values:
        spf = spf_values[0].lower()
        if "+all" in spf:
            findings["spf"]["policy"] = "+all"
            findings["spf"]["severity"] = "CRITICAL"
            findings["spf"]["strict"] = False
        elif "?all" in spf:
            findings["spf"]["policy"] = "?all"
            findings["spf"]["severity"] = "MEDIUM"
            findings["spf"]["strict"] = False
        elif "~all" in spf:
            findings["spf"]["policy"] = "~all"
            findings["spf"]["severity"] = "LOW"
            findings["spf"]["strict"] = True
        elif "-all" in spf:
            findings["spf"]["policy"] = "-all"
            findings["spf"]["severity"] = "PASS"
            findings["spf"]["strict"] = True
        else:
            findings["spf"]["policy"] = "missing-all"
            findings["spf"]["severity"] = "HIGH"

    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_raw = _resolve_records(_resolver(4), dmarc_domain, "TXT")
        dmarc_values = _extract_txt_like(dmarc_raw)
    except Exception:
        dmarc_values = []

    dmarc_entry = next((txt for txt in dmarc_values if txt.lower().startswith("v=dmarc1")), None)
    findings["dmarc"]["present"] = bool(dmarc_entry)
    findings["dmarc"]["record"] = dmarc_entry
    if dmarc_entry:
        dmarc_lower = dmarc_entry.lower()
        if "p=reject" in dmarc_lower:
            findings["dmarc"]["policy"] = "reject"
            findings["dmarc"]["strict"] = True
        elif "p=quarantine" in dmarc_lower:
            findings["dmarc"]["policy"] = "quarantine"
            findings["dmarc"]["strict"] = True
        elif "p=none" in dmarc_lower:
            findings["dmarc"]["policy"] = "none"
            findings["dmarc"]["strict"] = False
        else:
            findings["dmarc"]["policy"] = "unknown"
            findings["dmarc"]["strict"] = False

    return findings


def _zone_transfer(domain, nameservers, timeout):
    results = {}
    for ns in nameservers[:5]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=min(timeout, 4), lifetime=min(timeout, 6)))
            if zone:
                names = [str(name) for name in zone.nodes.keys()][:100]
                results[ns] = {"status": "success", "records_exposed": len(names), "sample": names[:20]}
            else:
                results[ns] = {"status": "failed"}
        except Exception:
            results[ns] = {"status": "failed"}
    return results


def run(url, domain, timeout=10):
    section("DNS Reconnaissance", "🔍")
    results = {"records": {}, "security": {}, "zone_transfer": {}, "risks": [],
               "dkim": {}, "dnssec": {}, "dangling_cnames": []}

    if not _DNS_AVAILABLE:
        error("dnspython not installed. Run: pip install dnspython")
        return {"error": "dnspython not installed"}

    resolver = _resolver(timeout)
    nameservers = []

    record_data = {}
    with ThreadPoolExecutor(max_workers=min(8, len(RECORD_TYPES))) as executor:
        future_to_rtype = {executor.submit(_fetch_record, resolver, domain, rtype): rtype for rtype in RECORD_TYPES}
        for future in as_completed(future_to_rtype):
            rtype, values, err = future.result()
            record_data[rtype] = (values, err)

    for rtype in RECORD_TYPES:
        values, err = record_data.get(rtype, ([], None))
        if err == "NXDOMAIN":
            error(f"Domain '{domain}' does not exist.")
            return {"error": "NXDOMAIN"}
        elif err:
            warn(err)
            results["records"][rtype] = []
        elif values:
            info(rtype, ", ".join(values[:6]) + (f" ... (+{len(values)-6})" if len(values) > 6 else ""))
            results["records"][rtype] = values
            if rtype == "NS":
                nameservers = [v.rstrip(".") for v in values]
        else:
            print(f"{Colors.DIM}[ ] {rtype}: No records{Colors.RESET}")
            results["records"][rtype] = []

    txt_records = _extract_txt_like(results["records"].get("TXT", []))
    security = _security_posture(domain, txt_records)
    results["security"] = security

    if not security["spf"]["present"]:
        warn("SPF record missing — email spoofing possible.")
        results["risks"].append("No SPF record")
    else:
        policy = security["spf"].get("policy", "")
        severity = security["spf"].get("severity", "")
        if severity == "CRITICAL":
            color = Colors.RED
            warn("SPF policy '+all' — CRITICAL: anyone can send email as this domain!")
            results["risks"].append("SPF +all: email spoofing fully open")
        elif severity == "MEDIUM":
            warn("SPF policy '?all' — neutral, offers no real protection.")
            results["risks"].append("Weak SPF policy: ?all")
        elif severity == "LOW":
            warn("SPF policy '~all' (softfail) — mail may not be rejected.")
            results["risks"].append("Weak SPF policy: ~all (softfail)")
        elif severity == "PASS":
            info("SPF", f"{Colors.GREEN}Present (-all, strict){Colors.RESET}")
        else:
            warn("SPF present but 'all' mechanism missing.")

    if not security["dmarc"]["present"]:
        warn("DMARC record missing — email spoofing protection absent.")
        results["risks"].append("No DMARC record")
    elif not security["dmarc"]["strict"]:
        policy = security["dmarc"].get("policy", "none")
        warn(f"DMARC present but policy is '{policy}' — not enforcing rejection.")
        results["risks"].append(f"Weak DMARC policy: p={policy}")
    else:
        policy = security["dmarc"].get("policy", "")
        info("DMARC", f"{Colors.GREEN}Present (p={policy}){Colors.RESET}")

    # --- DKIM ---
    print(f"\n{Colors.BOLD}  DKIM Check:{Colors.RESET}")
    dkim_found = _check_dkim(domain, timeout)
    results["dkim"] = {"found_selectors": dkim_found}
    if dkim_found:
        info("DKIM", f"{Colors.GREEN}Found on selectors: {', '.join(dkim_found)}{Colors.RESET}")
    else:
        warn("No DKIM record found on common selectors — email integrity not guaranteed.")
        results["risks"].append("No DKIM record found")

    # --- DNSSEC ---
    dnssec_enabled, ds_records = _check_dnssec(domain, timeout)
    results["dnssec"] = {"enabled": dnssec_enabled, "ds_records": ds_records}
    if dnssec_enabled:
        info("DNSSEC", f"{Colors.GREEN}Enabled (DS records present){Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[ ] DNSSEC: Not enabled (informational){Colors.RESET}")

    # --- Dangling CNAME detection ---
    cname_records = results["records"].get("CNAME", [])
    if cname_records:
        dangling = _check_dangling_cnames(domain, cname_records, timeout)
        results["dangling_cnames"] = dangling
        for d in dangling:
            warn(f"Potential subdomain takeover — CNAME '{d['cname']}' points to unresolvable host: {d['target']}")
            results["risks"].append(f"Dangling CNAME -> {d['target']}")

    # --- Zone transfer ---
    if nameservers:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Attempting DNS zone transfer on up to {min(len(nameservers), 5)} nameserver(s)...")
        zone_results = _zone_transfer(domain, nameservers, timeout)
        results["zone_transfer"] = zone_results
        for ns, detail in zone_results.items():
            if detail.get("status") == "success":
                warn(f"Zone transfer SUCCESSFUL on {ns} ({detail.get('records_exposed', 0)} records exposed).")
                results["risks"].append(f"Zone transfer enabled on {ns}")
            else:
                print(f"{Colors.DIM}[ ] Zone transfer failed on {ns} (expected){Colors.RESET}")

    return results
