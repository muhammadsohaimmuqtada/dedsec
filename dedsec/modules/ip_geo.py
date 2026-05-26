from dedsec.core.utils import cached_resolve_ipv4, error, info, safe_request, section, warn


def run(url, domain, timeout=10):
    section("IP & GeoLocation", "🌍")
    results = {}

    ip = cached_resolve_ipv4(domain)
    if not ip:
        error("Could not resolve IP.")
        return results
    info("IP Address", ip)
    results["ip"] = ip

    try:
        api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as"
        resp = safe_request(api_url, timeout=timeout)
        if not resp:
            raise RuntimeError("request failed")
        data = resp.json()

        if data.get("status") == "success":
            fields = {
                "Country":      data.get("country", "N/A"),
                "Region":       data.get("regionName", "N/A"),
                "City":         data.get("city", "N/A"),
                "ZIP":          data.get("zip", "N/A"),
                "Latitude":     str(data.get("lat", "N/A")),
                "Longitude":    str(data.get("lon", "N/A")),
                "Timezone":     data.get("timezone", "N/A"),
                "ISP":          data.get("isp", "N/A"),
                "Organization": data.get("org", "N/A"),
                "ASN":          data.get("as", "N/A"),
            }
            for key, value in fields.items():
                info(key, value)
                results[key.lower().replace(" ", "_")] = value
        else:
            warn(f"GeoIP API error: {data.get('message', 'unknown')}")
            results["geo_error"] = data.get("message", "unknown")
    except Exception as e:
        error(f"GeoIP lookup failed: {e}")
        results["geo_error"] = str(e)

    return results
