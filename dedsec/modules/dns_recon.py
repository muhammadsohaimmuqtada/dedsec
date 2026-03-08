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


def _security_posture(domain, txt_records):
    findings = {"spf": {"present": False, "strict": False}, "dmarc": {"present": False, "strict": False}}

    spf_values = [txt for txt in txt_records if txt.lower().startswith("v=spf1")]
    findings["spf"]["present"] = bool(spf_values)
    if spf_values:
        spf = spf_values[0].lower()
        findings["spf"]["strict"] = any(token in spf for token in (" -all", " ~all"))

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
        findings["dmarc"]["strict"] = ("p=reject" in dmarc_lower) or ("p=quarantine" in dmarc_lower)

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
    results = {"records": {}, "security": {}, "zone_transfer": {}, "risks": []}

    if not _DNS_AVAILABLE:
        error("dnspython not installed. Run: pip install dnspython")
        return {"error": "dnspython not installed"}

    resolver = _resolver(timeout)
    nameservers = []

    for rtype in RECORD_TYPES:
        try:
            values = _resolve_records(resolver, domain, rtype)
            if values:
                info(rtype, ", ".join(values[:6]) + (f" ... (+{len(values)-6})" if len(values) > 6 else ""))
            else:
                print(f"{Colors.DIM}[ ] {rtype}: No records{Colors.RESET}")
            results["records"][rtype] = values
            if rtype == "NS":
                nameservers = [value.rstrip(".") for value in values]
        except dns.resolver.NXDOMAIN:
            error(f"Domain '{domain}' does not exist.")
            return {"error": "NXDOMAIN"}
        except dns.resolver.NoNameservers:
            warn(f"{rtype} query failed: authoritative nameserver unavailable")
            results["records"][rtype] = []
        except dns.exception.Timeout:
            warn(f"{rtype} query timed out.")
            results["records"][rtype] = []
        except Exception as exc:
            warn(f"{rtype} query failed: {exc}")
            results["records"][rtype] = []

    txt_records = _extract_txt_like(results["records"].get("TXT", []))
    security = _security_posture(domain, txt_records)
    results["security"] = security

    if not security["spf"]["present"]:
        warn("SPF record missing.")
        results["risks"].append("No SPF record")
    elif not security["spf"]["strict"]:
        warn("SPF present but policy may be weak (missing ~all/-all).")
        results["risks"].append("Weak SPF policy")
    else:
        info("SPF", "Present")

    if not security["dmarc"]["present"]:
        warn("DMARC record missing.")
        results["risks"].append("No DMARC record")
    elif not security["dmarc"]["strict"]:
        warn("DMARC present but policy is not quarantine/reject.")
        results["risks"].append("Weak DMARC policy")
    else:
        info("DMARC", "Present with enforcement policy")

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
