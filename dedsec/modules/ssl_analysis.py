import socket
import ssl
from datetime import datetime, timezone

from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, section, warn

TLS_PROBES = [
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]


def _parse_cert_date(raw):
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _connect(domain, timeout, insecure=False):
    context = ssl.create_default_context()
    if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((domain, 443), timeout=timeout)
    conn = context.wrap_socket(sock, server_hostname=domain)
    # Get raw binary DER cert if we need details like signature algorithm / extensions
    der_cert = conn.getpeercert(binary_form=True)
    parsed_cert = conn.getpeercert()
    tls_version = conn.version()
    cipher = conn.cipher()
    
    # Try to grab the signature algorithm via cryptography parser if available
    sig_algo = "Unknown"
    has_sct = False
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())
        sig_algo = x509_cert.signature_algorithm_name
        # Extension OID for SCT (Signed Certificate Timestamps) is 1.3.6.1.4.1.11129.2.4.2
        try:
            x509_cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
            has_sct = True
        except Exception:
            pass
    except Exception:
        pass
        
    conn.close()
    return parsed_cert, tls_version, cipher, sig_algo, has_sct


def _probe_protocol(domain, timeout, version_attr):
    if not hasattr(ssl.TLSVersion, version_attr):
        return {"supported": False, "status": "unsupported-by-runtime"}
    version = getattr(ssl.TLSVersion, version_attr)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version
    try:
        sock = socket.create_connection((domain, 443), timeout=min(timeout, 4))
        conn = context.wrap_socket(sock, server_hostname=domain)
        negotiated = conn.version()
        conn.close()
        return {"supported": True, "status": "ok", "negotiated": negotiated}
    except Exception:
        return {"supported": False, "status": "blocked-or-unsupported"}


def run(url, domain, timeout=10):
    section("SSL/TLS Analysis", "🔒")
    results = {"risks": [], "protocol_support": {}}

    sig_algo = "Unknown"
    has_sct = False
    try:
        cert, protocol, cipher, sig_algo, has_sct = _connect(domain, timeout, insecure=False)
        hostname_valid = True
    except ssl.SSLCertVerificationError as exc:
        warn(f"Certificate verification failed: {exc}")
        results["risks"].append("Certificate verification failure")
        try:
            cert, protocol, cipher, sig_algo, has_sct = _connect(domain, timeout, insecure=True)
            hostname_valid = False
        except Exception as inner_exc:
            error(f"Could not establish TLS connection: {inner_exc}")
            return {"error": str(inner_exc)}
    except Exception as exc:
        error(f"TLS connection failed: {exc}")
        return {"error": str(exc)}

    if not cert:
        warn("No certificate data received.")
        return results

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))
    cn = subject.get("commonName", "N/A")
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    valid_from_raw = cert.get("notBefore", "")
    valid_until_raw = cert.get("notAfter", "")
    valid_from = _parse_cert_date(valid_from_raw)
    valid_until = _parse_cert_date(valid_until_raw)

    info("TLS Version", protocol or "Unknown")
    if cipher:
        info("Cipher", f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)")
    info("Common Name", cn)
    info("Issuer", issuer.get("commonName", "N/A"))
    info("Signature Algorithm", sig_algo)
    info("Valid From", valid_from_raw or "N/A")
    info("Valid Until", valid_until_raw or "N/A")
    info("Hostname Validation", "PASS" if hostname_valid else "FAILED")

    # 1. Self-signed certificate check
    is_self_signed = False
    if subject.get("commonName") == issuer.get("commonName") and subject.get("commonName") is not None:
        is_self_signed = True
        error("Self-signed certificate detected!")
        results["risks"].append("Self-signed certificate")
    else:
        results["is_self_signed"] = False

    # 2. SHA-1 signature algorithm check
    if any(m in sig_algo.lower() for m in ("sha1", "md5")):
        warn(f"Deprecated signature algorithm in use: {sig_algo}")
        results["risks"].append(f"Deprecated signature algorithm: {sig_algo}")

    # 3. SCT presence check
    results["has_sct"] = has_sct
    if has_sct:
        info("Certificate Transparency", f"{Colors.GREEN}SCT extension present{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}[ ] SCT extension not found (Certificate Transparency){Colors.RESET}")

    # 4. Wildcard check
    is_wildcard = cn.startswith("*.")
    results["is_wildcard"] = is_wildcard
    if is_wildcard:
        print(f"  {Colors.DIM}[ ] Wildcard certificate detected (*. CN){Colors.RESET}")

    now = datetime.now(timezone.utc)
    days_left = None
    if valid_until:
        days_left = (valid_until - now).days
        if days_left < 0:
            error(f"Certificate expired {abs(days_left)} days ago.")
            results["risks"].append("Certificate expired")
        elif days_left < 30:
            warn(f"Certificate expires in {days_left} days.")
            results["risks"].append("Certificate expires soon")
        else:
            info("Days Until Expiry", str(days_left))

    if protocol in {"TLSv1", "TLSv1.1"}:
        warn("Insecure TLS protocol negotiated.")
        results["risks"].append(f"Insecure negotiated protocol: {protocol}")

    weak_cipher_markers = ["RC4", "3DES", "DES", "NULL", "MD5"]
    if cipher and any(marker in cipher[0].upper() for marker in weak_cipher_markers):
        warn(f"Weak cipher detected: {cipher[0]}")
        results["risks"].append(f"Weak cipher: {cipher[0]}")

    for label, attr in TLS_PROBES:
        probe = _probe_protocol(domain, timeout, attr)
        results["protocol_support"][label] = probe

    if results["protocol_support"].get("TLSv1.0", {}).get("supported"):
        warn("Server still supports TLSv1.0.")
        results["risks"].append("TLSv1.0 supported")
    if results["protocol_support"].get("TLSv1.1", {}).get("supported"):
        warn("Server still supports TLSv1.1.")
        results["risks"].append("TLSv1.1 supported")

    if sans:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}SANs ({len(sans)} total):{Colors.RESET}")
        for san in sans[:15]:
            print(f"       {Colors.DIM}• {san}{Colors.RESET}")
        if len(sans) > 15:
            print(f"       {Colors.DIM}... and {len(sans)-15} more{Colors.RESET}")

    results.update(
        {
            "cn": cn,
            "issuer": issuer.get("commonName", "N/A"),
            "valid_from": valid_from_raw,
            "valid_until": valid_until_raw,
            "days_left": days_left,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "hostname_valid": hostname_valid,
            "san_count": len(sans),
            "sans": sans[:15],
            "sig_algo": sig_algo,
            "self_signed": is_self_signed,
        }
    )
    return results
