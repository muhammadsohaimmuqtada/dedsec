import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, section, warn

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
MAX_RECORDS_PER_TYPE = 25
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "s1", "s2", "mailjet",
    "sendgrid", "amazonses", "selector1", "selector2", "smtp", "email", "key1", "key2",
]

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
    resolver.lifetime = min(timeout, 8)
    return resolver


def _resolve_records(resolver, domain, rtype):
    answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
    if not answers:
        return []
    return [str(rdata).strip() for rdata in answers][:MAX_RECORDS_PER_TYPE]


def _fetch_record(resolver, domain, rtype):
    try:
        return rtype, _resolve_records(resolver, domain, rtype), None
    except dns.resolver.NXDOMAIN:
        return rtype, [], "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return rtype, [], "authoritative nameserver unavailable"
    except dns.exception.Timeout:
        return rtype, [], "query timed out"
    except Exception as exc:
        return rtype, [], f"query failed: {exc}"


def _extract_txt_like(values):
    return [value.strip('"').replace('" "', "") for value in values]


def _check_dkim(domain, timeout):
    found = []

    def _try_selector(selector):
        try:
            recs = _resolve_records(_resolver(timeout), f"{selector}._domainkey.{domain}", "TXT")
            if any("v=dkim1" in rec.lower() or "p=" in rec.lower() for rec in recs):
                return selector
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_try_selector, selector) for selector in DKIM_SELECTORS]
        for future in as_completed(futures):
            selector = future.result()
            if selector:
                found.append(selector)
    return sorted(found)


def _check_dnssec(domain, timeout):
    try:
        records = _resolve_records(_resolver(timeout), domain, "DS")
        return bool(records), records
    except Exception:
        return False, []


def _check_dangling_cnames(domain, cname_records):
    candidates = []
    for cname_target in cname_records:
        target = cname_target.rstrip(".")
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            candidates.append(
                {
                    "cname": domain,
                    "target": target,
                    "verified": False,
                    "classification": "dangling-dns-candidate",
                }
            )
        except Exception:
            pass
    return candidates


def _security_posture(domain, txt_records, timeout):
    posture = {
        "spf": {"present": False, "strict": False, "policy": None, "severity": None},
        "dmarc": {"present": False, "strict": False, "policy": None, "record": None},
    }
    spf_values = [txt for txt in txt_records if txt.lower().startswith("v=spf1")]
    posture["spf"]["present"] = bool(spf_values)
    if spf_values:
        spf = spf_values[0].lower()
        for mechanism, severity, strict in [
            ("+all", "CRITICAL", False),
            ("?all", "MEDIUM", False),
            ("~all", "LOW", False),
            ("-all", "PASS", True),
        ]:
            if mechanism in spf:
                posture["spf"].update(policy=mechanism, severity=severity, strict=strict)
                break
        if posture["spf"]["policy"] is None:
            posture["spf"].update(policy="missing-all", severity="MEDIUM", strict=False)

    try:
        dmarc_values = _extract_txt_like(
            _resolve_records(_resolver(timeout), f"_dmarc.{domain}", "TXT")
        )
    except Exception:
        dmarc_values = []
    record = next((item for item in dmarc_values if item.lower().startswith("v=dmarc1")), None)
    posture["dmarc"]["present"] = bool(record)
    posture["dmarc"]["record"] = record
    if record:
        lower = record.lower()
        if "p=reject" in lower:
            posture["dmarc"].update(policy="reject", strict=True)
        elif "p=quarantine" in lower:
            posture["dmarc"].update(policy="quarantine", strict=True)
        elif "p=none" in lower:
            posture["dmarc"].update(policy="none", strict=False)
        else:
            posture["dmarc"].update(policy="unknown", strict=False)
    return posture


def _zone_transfer(domain, nameservers, timeout):
    results = {}
    for ns in nameservers[:2]:
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns, domain, timeout=min(timeout, 4), lifetime=min(timeout, 6))
            )
            names = [str(name) for name in zone.nodes.keys()][:100] if zone else []
            results[ns] = {
                "status": "success" if zone else "failed",
                "records_exposed": len(names),
                "sample": names[:20],
            }
        except Exception:
            results[ns] = {"status": "failed"}
    return results


def run(url, domain, timeout=10):
    section("DNS Reconnaissance", "🔍")
    results = {
        "records": {},
        "security": {},
        "zone_transfer": {},
        "risks": [],
        "observations": [],
        "dkim": {},
        "dnssec": {},
        "dangling_cnames": [],
    }
    if not _DNS_AVAILABLE:
        error("dnspython not installed. Run: pip install dnspython")
        return {"error": "dnspython not installed"}

    resolver = _resolver(timeout)
    record_data = {}
    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as executor:
        futures = {
            executor.submit(_fetch_record, resolver, domain, rtype): rtype
            for rtype in RECORD_TYPES
        }
        for future in as_completed(futures):
            rtype, values, failure = future.result()
            record_data[rtype] = (values, failure)

    nameservers = []
    for rtype in RECORD_TYPES:
        values, failure = record_data.get(rtype, ([], None))
        if failure == "NXDOMAIN":
            error(f"Domain '{domain}' does not exist.")
            return {"error": "NXDOMAIN"}
        if failure:
            warn(f"{rtype} {failure}")
        elif values:
            info(rtype, ", ".join(values[:6]) + (f" ... (+{len(values)-6})" if len(values) > 6 else ""))
        else:
            print(f"{Colors.DIM}[ ] {rtype}: No records{Colors.RESET}")
        results["records"][rtype] = values
        if rtype == "NS":
            nameservers = [value.rstrip(".") for value in values]

    posture = _security_posture(domain, _extract_txt_like(results["records"].get("TXT", [])), timeout)
    results["security"] = posture
    if not posture["spf"]["present"]:
        warn("SPF record not present (email-domain posture observation).")
        results["observations"].append("SPF record not present")
    elif posture["spf"]["severity"] in {"CRITICAL", "MEDIUM", "LOW"}:
        results["risks"].append(f"SPF policy: {posture['spf']['policy']}")
        warn(f"SPF policy is {posture['spf']['policy']}")
    else:
        info("SPF", "Strict policy detected")

    if not posture["dmarc"]["present"]:
        warn("DMARC record not present (email-domain posture observation).")
        results["observations"].append("DMARC record not present")
    elif not posture["dmarc"]["strict"]:
        results["risks"].append(f"DMARC policy: {posture['dmarc']['policy']}")
        warn(f"DMARC policy is {posture['dmarc']['policy']}")
    else:
        info("DMARC", f"Enforced policy p={posture['dmarc']['policy']}")

    print(f"\n{Colors.BOLD}  DKIM Discovery:{Colors.RESET}")
    dkim_found = _check_dkim(domain, timeout)
    results["dkim"] = {
        "found_selectors": dkim_found,
        "tested_selectors": list(DKIM_SELECTORS),
        "complete": False,
    }
    if dkim_found:
        info("DKIM", f"Found on tested selector(s): {', '.join(dkim_found)}")
    else:
        print(
            f"  {Colors.DIM}[ ] No DKIM record discovered on the tested common selectors; DKIM absence is not proven.{Colors.RESET}"
        )

    dnssec_enabled, ds_records = _check_dnssec(domain, timeout)
    results["dnssec"] = {"enabled": dnssec_enabled, "ds_records": ds_records}
    if dnssec_enabled:
        info("DNSSEC", "Enabled (DS records present)")
    else:
        print(f"  {Colors.DIM}[ ] DNSSEC: no DS record observed{Colors.RESET}")

    cname_records = results["records"].get("CNAME", [])
    if cname_records:
        dangling = _check_dangling_cnames(domain, cname_records)
        results["dangling_cnames"] = dangling
        for item in dangling:
            warn(
                f"Dangling CNAME candidate: {item['cname']} -> {item['target']} (claimability not verified)"
            )

    if nameservers:
        print(
            f"\n{Colors.YELLOW}[!]{Colors.RESET} Active DNS check: attempting AXFR on up to {min(len(nameservers), 2)} authoritative nameserver(s)..."
        )
        zone_results = _zone_transfer(domain, nameservers, timeout)
        results["zone_transfer"] = {
            "active_probe": True,
            "nameservers": zone_results,
        }
        for ns, detail in zone_results.items():
            if detail.get("status") == "success":
                warn(f"Zone transfer succeeded on {ns} ({detail.get('records_exposed', 0)} records).")
                results["risks"].append(f"Zone transfer enabled on {ns}")
            else:
                print(f"{Colors.DIM}[ ] Zone transfer failed on {ns} (expected){Colors.RESET}")
    return results
