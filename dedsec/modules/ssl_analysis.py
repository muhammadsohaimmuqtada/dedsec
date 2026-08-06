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


def _parse_der_details(der_cert):
    """Return optional certificate details without making them a hard dependency."""
    details = {"signature_algorithm": None, "sct_present": None, "parser": "stdlib"}
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(der_cert)
        details["signature_algorithm"] = getattr(certificate, "signature_algorithm_oid", None)
        if details["signature_algorithm"] is not None:
            details["signature_algorithm"] = details["signature_algorithm"]._name or details["signature_algorithm"].dotted_string
        details["parser"] = "cryptography"
        try:
            certificate.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
            )
            details["sct_present"] = True
        except x509.ExtensionNotFound:
            details["sct_present"] = False
        except Exception:
            details["sct_present"] = None
    except Exception:
        pass
    return details


def _connect(domain, timeout, insecure=False):
    # insecure is retained in the signature for compatibility but intentionally
    # rejected: production TLS collection never falls back to CERT_NONE.
    if insecure:
        raise ValueError("insecure TLS fallback is disabled")
    context = ssl.create_default_context()
    if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as conn:
            der_cert = conn.getpeercert(binary_form=True)
            parsed_cert = conn.getpeercert()
            tls_version = conn.version()
            cipher = conn.cipher()
    details = _parse_der_details(der_cert)
    return (
        parsed_cert,
        tls_version,
        cipher,
        details["signature_algorithm"],
        details["sct_present"],
    )


def _probe_protocol(domain, timeout, version_attr):
    if not hasattr(ssl, "TLSVersion") or not hasattr(ssl.TLSVersion, version_attr):
        return {"supported": False, "status": "unsupported-by-runtime"}
    version = getattr(ssl.TLSVersion, version_attr)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version
    try:
        with socket.create_connection((domain, 443), timeout=min(timeout, 4)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as conn:
                negotiated = conn.version()
        return {"supported": True, "status": "ok", "negotiated": negotiated}
    except Exception:
        return {"supported": False, "status": "blocked-or-unsupported"}


def run(url, domain, timeout=10):
    section("SSL/TLS Analysis", "🔒")
    results = {"risks": [], "observations": [], "protocol_support": {}}

    try:
        cert, protocol, cipher, sig_algo, has_sct = _connect(domain, timeout, insecure=False)
    except ssl.SSLCertVerificationError as exc:
        error(f"Certificate verification failed: {exc}")
        return {
            "error": f"certificate verification failed: {exc}",
            "risks": ["Certificate verification failure"],
            "hostname_valid": False,
        }
    except Exception as exc:
        error(f"TLS connection failed: {exc}")
        return {"error": str(exc)}

    if not cert:
        return {"error": "No verified certificate data received"}

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))
    cn = subject.get("commonName", "N/A")
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    valid_from_raw = cert.get("notBefore", "")
    valid_until_raw = cert.get("notAfter", "")
    valid_until = _parse_cert_date(valid_until_raw)

    info("TLS Version", protocol or "Unknown")
    if cipher:
        info("Cipher", f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)")
    info("Common Name", cn)
    info("Issuer", issuer.get("commonName", "N/A"))
    if sig_algo:
        info("Signature Algorithm", sig_algo)
    else:
        print(f"  {Colors.DIM}[ ] Signature algorithm detail unavailable in current runtime{Colors.RESET}")
    info("Valid From", valid_from_raw or "N/A")
    info("Valid Until", valid_until_raw or "N/A")
    info("Hostname Validation", "PASS")

    is_self_signed = (
        subject.get("commonName") is not None
        and subject.get("commonName") == issuer.get("commonName")
    )
    if is_self_signed:
        error("Self-signed certificate detected.")
        results["risks"].append("Self-signed certificate")

    if sig_algo and any(marker in sig_algo.lower() for marker in ("sha1", "md5")):
        warn(f"Deprecated signature algorithm in use: {sig_algo}")
        results["risks"].append(f"Deprecated signature algorithm: {sig_algo}")

    if has_sct is True:
        info("Certificate Transparency", f"{Colors.GREEN}SCT extension present{Colors.RESET}")
        sct_status = "present"
    elif has_sct is False:
        print(f"  {Colors.DIM}[ ] SCT extension not present in leaf certificate{Colors.RESET}")
        sct_status = "not-present"
    else:
        print(f"  {Colors.DIM}[ ] SCT extension status unavailable in current runtime{Colors.RESET}")
        sct_status = "unknown"

    now = datetime.now(timezone.utc)
    days_left = None
    if valid_until:
        days_left = (valid_until - now).days
        if days_left < 0:
            error(f"Certificate expired {abs(days_left)} days ago.")
            results["risks"].append("Certificate expired")
        elif days_left < 30:
            warn(f"Certificate expires in {days_left} days.")
            results["observations"].append("Certificate expires within 30 days")
        else:
            info("Days Until Expiry", str(days_left))

    weak_cipher_markers = ["RC4", "3DES", "DES", "NULL", "MD5"]
    if cipher and any(marker in cipher[0].upper() for marker in weak_cipher_markers):
        warn(f"Weak cipher detected: {cipher[0]}")
        results["risks"].append(f"Weak cipher: {cipher[0]}")

    for label, attr in TLS_PROBES:
        results["protocol_support"][label] = _probe_protocol(domain, timeout, attr)
    for legacy in ("TLSv1.0", "TLSv1.1"):
        if results["protocol_support"].get(legacy, {}).get("supported"):
            warn(f"Server still supports {legacy}.")
            results["risks"].append(f"{legacy} supported")

    if sans:
        print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}SANs ({len(sans)} total):{Colors.RESET}")
        for san in sans[:15]:
            print(f"       {Colors.DIM}• {san}{Colors.RESET}")

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
            "hostname_valid": True,
            "san_count": len(sans),
            "sans": sans[:15],
            "sig_algo": sig_algo,
            "signature_algorithm_available": sig_algo is not None,
            "has_sct": has_sct,
            "sct_status": sct_status,
            "is_self_signed": is_self_signed,
            "self_signed": is_self_signed,
            "is_wildcard": cn.startswith("*."),
        }
    )
    return results
