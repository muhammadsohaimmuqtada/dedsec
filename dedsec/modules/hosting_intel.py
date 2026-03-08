import socket

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

PROVIDER_PATTERNS = {
    "Amazon Web Services": ["amazon", "aws", "ec2"],
    "Google Cloud": ["google", "gcp", "google cloud"],
    "Microsoft Azure": ["microsoft", "azure"],
    "Cloudflare": ["cloudflare"],
    "DigitalOcean": ["digitalocean"],
    "OVH": ["ovh"],
    "Hetzner": ["hetzner"],
    "Akamai": ["akamai"],
}


def _classify_provider(asn_text, org_text):
    haystack = f"{asn_text} {org_text}".lower()
    for provider, patterns in PROVIDER_PATTERNS.items():
        if any(pattern in haystack for pattern in patterns):
            return provider
    return "Unknown/Unclassified"


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _ip_metadata(ip, timeout):
    api_url = f"http://ip-api.com/json/{ip}?fields=status,message,isp,org,as,asname,hosting,proxy,mobile"
    resp = safe_request(api_url, timeout=timeout)
    if not resp:
        return {"error": "metadata request failed"}

    try:
        data = resp.json()
    except Exception:
        return {"error": "invalid metadata response"}

    if data.get("status") != "success":
        return {"error": data.get("message", "metadata error")}

    asn = data.get("as", "N/A")
    org = data.get("org", "N/A")
    return {
        "isp": data.get("isp", "N/A"),
        "org": org,
        "asn": asn,
        "as_name": data.get("asname", "N/A"),
        "hosting": bool(data.get("hosting", False)),
        "proxy": bool(data.get("proxy", False)),
        "mobile": bool(data.get("mobile", False)),
        "provider_guess": _classify_provider(asn, org),
    }


def _resolve_ips(domain):
    ips = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            for entry in infos:
                ips.add(entry[4][0])
        except Exception:
            continue
    return sorted(ips)


def run(url, domain, timeout=10):
    section("Hosting Intelligence", "🏢")
    results = {"ips": [], "cdn_signals": [], "provider_summary": []}

    resp = safe_request(url, timeout=timeout)
    headers = {k.lower(): v.lower() for k, v in (resp.headers.items() if resp else [])}

    cdn_signals = []
    if "cf-ray" in headers or "cloudflare" in headers.get("server", ""):
        cdn_signals.append("Cloudflare edge detected")
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", ""):
        cdn_signals.append("CloudFront edge detected")
    if "akamai" in headers.get("server", "") or "x-akamai-transformed" in headers:
        cdn_signals.append("Akamai edge detected")

    for signal in cdn_signals:
        info("CDN Signal", signal)
    results["cdn_signals"] = cdn_signals

    ips = _resolve_ips(domain)
    if not ips:
        warn("Could not resolve target IPs.")
        return results

    provider_counts = {}
    for ip in ips:
        rdns = _reverse_dns(ip)
        metadata = _ip_metadata(ip, timeout)
        provider = metadata.get("provider_guess", "Unknown/Unclassified")
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

        info("Resolved IP", ip)
        if rdns:
            info("Reverse DNS", rdns)
        if "error" in metadata:
            warn(f"Metadata unavailable for {ip}: {metadata['error']}")
        else:
            info("Provider Guess", provider)
            print(
                f"{Colors.DIM}    ASN={metadata['asn']} ISP={metadata['isp']} Hosting={metadata['hosting']} "
                f"Proxy={metadata['proxy']}{Colors.RESET}"
            )

        results["ips"].append({"ip": ip, "reverse_dns": rdns, "metadata": metadata})

    summary = [f"{name}: {count}" for name, count in sorted(provider_counts.items(), key=lambda item: (-item[1], item[0]))]
    if summary:
        info("Provider Summary", ", ".join(summary))
    results["provider_summary"] = summary
    return results
