from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(url, domain, timeout=10):
    section("DNS Reconnaissance", "🔍")
    results = {}

    try:
        import dns.resolver
        import dns.zone
        import dns.query
        import dns.exception
    except ImportError:
        error("dnspython not installed. Run: pip install dnspython")
        return {"error": "dnspython not installed"}

    nameservers = []

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=timeout)
            records = []
            for rdata in answers:
                records.append(str(rdata))
            info(rtype, ", ".join(records))
            results[rtype] = records
            if rtype == "NS":
                nameservers = [r.rstrip(".") for r in records]
        except dns.resolver.NoAnswer:
            print(f"{Colors.DIM}[ ] {rtype}: No records{Colors.RESET}")
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            error(f"Domain '{domain}' does not exist.")
            results["error"] = "NXDOMAIN"
            return results
        except dns.exception.Timeout:
            warn(f"{rtype} query timed out.")
            results[rtype] = []
        except Exception as e:
            warn(f"{rtype} query failed: {e}")
            results[rtype] = []

    # Zone transfer attempt
    zone_results = {}
    if nameservers:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Attempting DNS zone transfer on {len(nameservers)} nameserver(s)...")
        for ns in nameservers:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
                names = [str(n) for n in z.nodes.keys()]
                warn(f"Zone transfer SUCCESSFUL on {ns}! Exposed {len(names)} records.")
                zone_results[ns] = names
            except Exception:
                print(f"{Colors.DIM}[ ] Zone transfer failed on {ns} (expected){Colors.RESET}")
                zone_results[ns] = "refused"

    results["zone_transfer"] = zone_results
    return results
