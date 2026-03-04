import socket
import requests
from dedsec.core.utils import section, info, warn, error
from dedsec.core.colors import Colors


def run(url, domain, timeout=10):
    section("IP & GeoLocation", "🌍")
    results = {}

    try:
        ip = socket.gethostbyname(domain)
        info("IP Address", ip)
        results["ip"] = ip
    except socket.gaierror as e:
        error(f"Could not resolve IP: {e}")
        return results

    try:
        api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as"
        resp = requests.get(api_url, timeout=timeout)
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
