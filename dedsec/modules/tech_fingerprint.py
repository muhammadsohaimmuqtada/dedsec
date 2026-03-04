import re
from dedsec.core.utils import safe_request, section, info, warn, error
from dedsec.core.colors import Colors

SIGNATURES = {
    "languages": {
        "PHP":     {"headers": {"x-powered-by": "php"}, "body": [], "cookies": ["PHPSESSID"]},
        "ASP.NET": {"headers": {"x-powered-by": "asp.net", "x-aspnet-version": None}, "body": [], "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"]},
        "Python":  {"headers": {"x-powered-by": "python"}, "body": ["django", "flask", "wsgi"], "cookies": []},
        "Java":    {"headers": {"x-powered-by": "jsp", "x-powered-by": "servlet"}, "body": ["javax.faces", "jsf", "struts"], "cookies": ["JSESSIONID"]},
        "Ruby":    {"headers": {"x-powered-by": "phusion passenger"}, "body": ["ruby on rails", "rack"], "cookies": ["_session_id"]},
        "Node.js": {"headers": {"x-powered-by": "express"}, "body": [], "cookies": []},
    },
    "servers": {
        "Apache":    {"headers": {"server": "apache"}, "body": [], "cookies": []},
        "Nginx":     {"headers": {"server": "nginx"}, "body": [], "cookies": []},
        "IIS":       {"headers": {"server": "microsoft-iis"}, "body": [], "cookies": []},
        "LiteSpeed": {"headers": {"server": "litespeed"}, "body": [], "cookies": []},
        "Caddy":     {"headers": {"server": "caddy"}, "body": [], "cookies": []},
        "Tomcat":    {"headers": {"server": "apache-coyote", "server": "tomcat"}, "body": ["apache tomcat"], "cookies": []},
    },
    "cms": {
        "WordPress":    {"headers": {"x-powered-by": "wordpress"}, "body": ["/wp-content/", "/wp-includes/", "wp-json"], "cookies": ["wordpress_", "wp-settings"]},
        "Joomla":       {"headers": {}, "body": ["/components/com_", "joomla"], "cookies": ["joomla_session"]},
        "Drupal":       {"headers": {"x-generator": "drupal", "x-drupal-cache": None}, "body": ["drupal.settings", "/sites/default/files/"], "cookies": ["SESS", "Drupal.visitor"]},
        "Shopify":      {"headers": {"x-shopify-stage": None}, "body": ["cdn.shopify.com", "shopify.com/s/files"], "cookies": ["_shopify_"]},
        "Magento":      {"headers": {}, "body": ["magento", "mage/cookies", "varien/js"], "cookies": ["frontend", "adminhtml"]},
        "Wix":          {"headers": {}, "body": ["wix.com", "X-Wix-Published-Version", "static.wixstatic.com"], "cookies": []},
        "Squarespace":  {"headers": {}, "body": ["squarespace.com", "static1.squarespace.com"], "cookies": ["crumb"]},
    },
    "js_frameworks": {
        "React":    {"headers": {}, "body": ["react", "reactdom", "__reactFiber", "data-reactroot"], "cookies": []},
        "Angular":  {"headers": {}, "body": ["ng-version", "angular.js", "ng-app", "_nghost"], "cookies": []},
        "Vue.js":   {"headers": {}, "body": ["vue.js", "vue.min.js", "__vue__", "data-v-"], "cookies": []},
        "jQuery":   {"headers": {}, "body": ["jquery.js", "jquery.min.js", "jquery-"], "cookies": []},
        "Next.js":  {"headers": {"x-powered-by": "next.js"}, "body": ["__NEXT_DATA__", "_next/static"], "cookies": []},
        "Nuxt.js":  {"headers": {}, "body": ["__nuxt", "__NUXT__", "_nuxt/"], "cookies": []},
        "Svelte":   {"headers": {}, "body": ["svelte", "__svelte"], "cookies": []},
    },
    "cdn": {
        "Cloudflare":       {"headers": {"server": "cloudflare", "cf-ray": None}, "body": [], "cookies": []},
        "CloudFront":       {"headers": {"x-amz-cf-id": None, "via": "cloudfront"}, "body": [], "cookies": []},
        "Fastly":           {"headers": {"x-served-by": None, "fastly-restarts": None, "x-cache": None}, "body": [], "cookies": []},
        "Akamai":           {"headers": {"x-check-cacheable": None, "akamai-origin-hop": None}, "body": [], "cookies": []},
        "Google Cloud CDN": {"headers": {"x-goog-generation": None, "via": "google"}, "body": [], "cookies": []},
    },
    "analytics": {
        "Google Analytics": {"headers": {}, "body": ["google-analytics.com/analytics.js", "gtag/js?id=", "UA-", "G-"], "cookies": ["_ga", "_gid", "_gat"]},
        "Google Tag Manager": {"headers": {}, "body": ["googletagmanager.com/gtm.js", "GTM-"], "cookies": []},
        "Facebook Pixel":   {"headers": {}, "body": ["connect.facebook.net/en_US/fbevents.js", "fbq("], "cookies": ["_fbp", "_fbc"]},
        "Hotjar":           {"headers": {}, "body": ["static.hotjar.com", "hjSiteSettings", "hj("], "cookies": ["_hjid", "_hjSessionUser"]},
    },
}


def _detect_category(category_name, sigs, headers_lower, body_lower, cookies_lower):
    found = []
    for name, patterns in sigs.items():
        matched = False
        for hdr, val in patterns.get("headers", {}).items():
            if hdr in headers_lower:
                if val is None or val in headers_lower[hdr]:
                    matched = True
                    break
        if not matched:
            for pattern in patterns.get("body", []):
                if pattern.lower() in body_lower:
                    matched = True
                    break
        if not matched:
            for ck in patterns.get("cookies", []):
                for cookie in cookies_lower:
                    if ck.lower() in cookie:
                        matched = True
                        break
                if matched:
                    break
        if matched:
            found.append(name)
    return found


def run(url, domain, timeout=10):
    section("Technology Fingerprinting", "🌐")
    results = {}

    resp = safe_request(url, timeout=timeout)
    if not resp:
        error("Could not connect to target.")
        return results

    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    cookies_lower = [c.lower() for c in resp.cookies.keys()]
    body_lower = resp.text.lower()

    category_labels = {
        "languages": "Languages",
        "servers": "Web Servers",
        "cms": "CMS",
        "js_frameworks": "JS Frameworks",
        "cdn": "CDN",
        "analytics": "Analytics",
    }

    for cat_key, cat_label in category_labels.items():
        found = _detect_category(cat_key, SIGNATURES[cat_key], headers_lower, body_lower, cookies_lower)
        if found:
            info(cat_label, ", ".join(f"{Colors.CYAN}{f}{Colors.RESET}" for f in found))
            results[cat_key] = found
        else:
            print(f"{Colors.DIM}[ ] {cat_label}: Not detected{Colors.RESET}")
            results[cat_key] = []

    # Extra: server version from headers
    if "server" in headers_lower:
        info("Server Header", headers_lower["server"])
        results["server_header"] = headers_lower["server"]
    if "x-powered-by" in headers_lower:
        info("X-Powered-By", headers_lower["x-powered-by"])
        results["x_powered_by"] = headers_lower["x-powered-by"]

    return results
