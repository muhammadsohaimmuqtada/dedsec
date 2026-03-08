import re

from dedsec.core.colors import Colors
from dedsec.core.utils import error, info, safe_request, section

SIGNATURES = {
    "languages": {
        "PHP": {"headers": {"x-powered-by": ["php"]}, "body": [], "cookies": ["phpsessid"]},
        "ASP.NET": {"headers": {"x-powered-by": ["asp.net"], "x-aspnet-version": [None]}, "body": [], "cookies": ["asp.net_sessionid", "aspsessionid"]},
        "Python": {"headers": {"x-powered-by": ["python", "gunicorn"]}, "body": [r"\bcsrfmiddlewaretoken\b", r"\b__wsgi__\b"], "cookies": []},
        "Java": {"headers": {"x-powered-by": ["jsp", "servlet"]}, "body": [r"\bjavax\.faces\b", r"\bjsessionid\b"], "cookies": ["jsessionid"]},
        "Ruby": {"headers": {"x-powered-by": ["phusion passenger", "ruby"]}, "body": [r"\bcsrf-param\b", r"\brails-ujs\b"], "cookies": ["_session_id"]},
        "Node.js": {"headers": {"x-powered-by": ["express", "next.js"]}, "body": [r"\b__next_data__\b"], "cookies": []},
    },
    "servers": {
        "Apache": {"headers": {"server": ["apache"]}, "body": [], "cookies": []},
        "Nginx": {"headers": {"server": ["nginx"]}, "body": [], "cookies": []},
        "IIS": {"headers": {"server": ["microsoft-iis"]}, "body": [], "cookies": []},
        "LiteSpeed": {"headers": {"server": ["litespeed"]}, "body": [], "cookies": []},
        "Caddy": {"headers": {"server": ["caddy"]}, "body": [], "cookies": []},
        "Tomcat": {"headers": {"server": ["apache-coyote", "tomcat"]}, "body": [r"\bapache tomcat\b"], "cookies": []},
    },
    "cms": {
        "WordPress": {"headers": {"x-powered-by": ["wordpress"]}, "body": [r"/wp-content/", r"/wp-includes/", r"\bwp-json\b"], "cookies": ["wordpress_", "wp-settings-"]},
        "Joomla": {"headers": {}, "body": [r"/components/com_", r'content="joomla!'], "cookies": ["joomla_"]},
        "Drupal": {"headers": {"x-generator": ["drupal"], "x-drupal-cache": [None]}, "body": [r"\bdrupalsettings\b", r"/sites/default/files/"], "cookies": ["sess", "sse"], "cookie_prefix": True},
        "Shopify": {"headers": {"x-shopify-stage": [None], "server-timing": ["processing;dur="]}, "body": [r"cdn\.shopify\.com", r"shopify\.section"], "cookies": ["_shopify_"]},
        "Magento": {"headers": {}, "body": [r"\bmage/cookies\b", r"\bvarien/js\b"], "cookies": ["frontend", "adminhtml"]},
        "Wix": {"headers": {"x-wix-request-id": [None]}, "body": [r"static\.wixstatic\.com"], "cookies": []},
        "Squarespace": {"headers": {"x-contextid": [None]}, "body": [r"static1\.squarespace\.com"], "cookies": ["crumb"]},
    },
    "js_frameworks": {
        "React": {"headers": {}, "body": [r"data-reactroot", r"__reactfiber", r"react-dom"], "cookies": []},
        "Angular": {"headers": {}, "body": [r"\bng-version\b", r"\bng-app\b", r"_nghost"], "cookies": []},
        "Vue.js": {"headers": {}, "body": [r"__vue__", r"data-v-[a-f0-9]{6,}", r"vue\.runtime"], "cookies": []},
        "jQuery": {"headers": {}, "body": [r"jquery(?:\.min)?\.js", r"jquery-\d+\.\d+\.\d+"], "cookies": []},
        "Next.js": {"headers": {"x-powered-by": ["next.js"]}, "body": [r"__next_data__", r"_next/static"], "cookies": []},
        "Nuxt.js": {"headers": {}, "body": [r"__nuxt__", r"_nuxt/"], "cookies": []},
        "Svelte": {"headers": {}, "body": [r"__svelte", r"sveltekit"], "cookies": []},
    },
    "cdn": {
        "Cloudflare": {"headers": {"server": ["cloudflare"], "cf-ray": [None]}, "body": [], "cookies": []},
        "CloudFront": {"headers": {"x-amz-cf-id": [None], "via": ["cloudfront"]}, "body": [], "cookies": []},
        "Fastly": {"headers": {"x-served-by": ["cache-"], "x-cache": ["fastly"]}, "body": [], "cookies": []},
        "Akamai": {"headers": {"x-akamai-transformed": [None], "akamai-origin-hop": [None]}, "body": [], "cookies": []},
        "Google Cloud CDN": {"headers": {"via": ["google"], "x-goog-generation": [None]}, "body": [], "cookies": []},
    },
    "analytics": {
        "Google Analytics": {"headers": {}, "body": [r"googletagmanager\.com/gtag/js\?id=g-[a-z0-9]+", r"google-analytics\.com/analytics\.js"], "cookies": ["_ga", "_gid"]},
        "Google Tag Manager": {"headers": {}, "body": [r"googletagmanager\.com/gtm\.js", r"\bgtm-[a-z0-9]+\b"], "cookies": []},
        "Facebook Pixel": {"headers": {}, "body": [r"connect\.facebook\.net/.*/fbevents\.js", r"\bfbq\("], "cookies": ["_fbp", "_fbc"]},
        "Hotjar": {"headers": {}, "body": [r"static\.hotjar\.com", r"\bhj[a-z]*\("], "cookies": ["_hjid", "_hjsessionuser"]},
    },
}


def _score_signature(patterns, headers_lower, body_lower, cookies_lower):
    score = 0
    evidence = []

    for header, expected_values in patterns.get("headers", {}).items():
        if header not in headers_lower:
            continue
        header_value = headers_lower[header]
        if any(expected is None or expected in header_value for expected in expected_values):
            score += 40
            evidence.append(f"header '{header}' matched")

    for body_pattern in patterns.get("body", []):
        if re.search(body_pattern, body_lower, re.IGNORECASE):
            score += 25
            evidence.append(f"body matched /{body_pattern}/")

    use_prefix_match = patterns.get("cookie_prefix", False)
    for cookie in patterns.get("cookies", []):
        matched = any(candidate.startswith(cookie) if use_prefix_match else cookie in candidate for candidate in cookies_lower)
        if matched:
            score += 35
            evidence.append(f"cookie '{cookie}' matched")

    return score, list(dict.fromkeys(evidence))


def _detect_category(sigs, headers_lower, body_lower, cookies_lower):
    found = []
    evidence_map = {}
    for name, patterns in sigs.items():
        score, evidence = _score_signature(patterns, headers_lower, body_lower, cookies_lower)
        if score >= 40:
            found.append((name, min(score, 100)))
            evidence_map[name] = evidence
    found.sort(key=lambda item: (-item[1], item[0]))
    return found, evidence_map


def run(url, domain, timeout=10):
    section("Technology Fingerprinting", "🌐")
    results = {}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    headers_lower = {key.lower(): value.lower() for key, value in resp.headers.items()}
    cookies_lower = [cookie.lower() for cookie in resp.cookies.keys()]
    body_lower = resp.text.lower()

    category_labels = {
        "languages": "Languages",
        "servers": "Web Servers",
        "cms": "CMS",
        "js_frameworks": "JS Frameworks",
        "cdn": "CDN",
        "analytics": "Analytics",
    }

    for category_key, category_label in category_labels.items():
        found, evidence_map = _detect_category(SIGNATURES[category_key], headers_lower, body_lower, cookies_lower)
        if found:
            rendered = []
            for name, score in found:
                rendered.append(f"{Colors.CYAN}{name}{Colors.RESET} ({score}%)")
            info(category_label, ", ".join(rendered))
            results[category_key] = [{"name": name, "confidence": f"{score}%", "evidence": evidence_map[name]} for name, score in found]
        else:
            print(f"{Colors.DIM}[ ] {category_label}: Not detected{Colors.RESET}")
            results[category_key] = []

    if "server" in headers_lower:
        info("Server Header", headers_lower["server"])
        results["server_header"] = headers_lower["server"]
    if "x-powered-by" in headers_lower:
        info("X-Powered-By", headers_lower["x-powered-by"])
        results["x_powered_by"] = headers_lower["x-powered-by"]

    return results
