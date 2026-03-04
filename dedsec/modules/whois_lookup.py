from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors


def run(url, domain, timeout=10):
    section("WHOIS Lookup", "🕵️")
    results = {}

    try:
        import whois
    except ImportError:
        error("python-whois not installed. Run: pip install python-whois")
        return {"error": "python-whois not installed"}

    try:
        w = whois.whois(domain)
    except Exception as e:
        error(f"WHOIS lookup failed: {e}")
        return {"error": str(e)}

    def fmt_date(val):
        if isinstance(val, list):
            val = val[0]
        if val is None:
            return "N/A"
        try:
            return str(val)
        except Exception:
            return "N/A"

    def fmt_list(val):
        if isinstance(val, list):
            return ", ".join(str(v) for v in val if v)
        return str(val) if val else "N/A"

    fields = {
        "Domain":      fmt_list(w.get("domain_name")),
        "Registrar":   fmt_list(w.get("registrar")),
        "Created":     fmt_date(w.get("creation_date")),
        "Expires":     fmt_date(w.get("expiration_date")),
        "Updated":     fmt_date(w.get("updated_date")),
        "Nameservers": fmt_list(w.get("name_servers")),
        "Status":      fmt_list(w.get("status")),
        "Org":         fmt_list(w.get("org")),
        "Country":     fmt_list(w.get("country")),
        "Emails":      fmt_list(w.get("emails")),
    }

    for key, value in fields.items():
        if value and value != "N/A":
            info(key, value)
        else:
            print(f"{Colors.DIM}[ ] {key}: N/A{Colors.RESET}")
        results[key.lower()] = value

    return results
