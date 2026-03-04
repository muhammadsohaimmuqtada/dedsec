import ssl
import socket
from datetime import datetime, timezone
from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors


def run(url, domain, timeout=10):
    section("SSL/TLS Analysis", "🔒")
    results = {}

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((domain, 443), timeout=timeout), server_hostname=domain)
        cert = conn.getpeercert()
        protocol = conn.version()
        conn.close()
    except ssl.SSLCertVerificationError as e:
        warn(f"SSL certificate verification failed: {e}")
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            conn2 = ctx2.wrap_socket(socket.create_connection((domain, 443), timeout=timeout), server_hostname=domain)
            cert = conn2.getpeercert()
            protocol = conn2.version()
            conn2.close()
        except Exception as e2:
            error(f"Could not connect via SSL: {e2}")
            return {"error": str(e2)}
    except Exception as e:
        error(f"SSL connection failed: {e}")
        return {"error": str(e)}

    # Subject
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))
    cn      = subject.get("commonName", "N/A")
    org     = subject.get("organizationName", "N/A")
    issuer_cn = issuer.get("commonName", "N/A")
    issuer_org = issuer.get("organizationName", "N/A")

    # Dates
    not_before_str = cert.get("notBefore", "")
    not_after_str  = cert.get("notAfter", "")
    fmt = "%b %d %H:%M:%S %Y %Z"
    now = datetime.now(timezone.utc)

    try:
        not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(not_after_str,  fmt).replace(tzinfo=timezone.utc)
        days_left  = (not_after - now).days
    except Exception:
        not_before = not_after = None
        days_left = None

    serial = cert.get("serialNumber", "N/A")

    info("Common Name",    cn)
    info("Organization",   org)
    info("Issuer",         f"{issuer_cn} ({issuer_org})")
    info("Valid From",     not_before_str)
    info("Valid Until",    not_after_str)
    info("Protocol",       protocol)
    info("Serial Number",  serial)

    if days_left is not None:
        if days_left < 0:
            error(f"Certificate EXPIRED {abs(days_left)} days ago!")
        elif days_left < 30:
            warn(f"Certificate expires in {days_left} days — renew soon!")
        elif days_left < 90:
            warn(f"Certificate expires in {days_left} days.")
        else:
            info("Days Until Expiry", f"{Colors.GREEN}{days_left}{Colors.RESET}")

    # SANs
    sans = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            sans.append(san_value)
    displayed_sans = sans[:20]
    if displayed_sans:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}SANs ({len(sans)} total):{Colors.RESET}")
        for s in displayed_sans:
            print(f"       {Colors.DIM}• {s}{Colors.RESET}")
        if len(sans) > 20:
            print(f"       {Colors.DIM}... and {len(sans)-20} more{Colors.RESET}")

    results = {
        "cn": cn,
        "org": org,
        "issuer": f"{issuer_cn} ({issuer_org})",
        "valid_from": not_before_str,
        "valid_until": not_after_str,
        "days_left": days_left,
        "protocol": protocol,
        "serial": serial,
        "sans": sans[:20],
        "san_count": len(sans),
    }
    return results
