from typing import Dict, Iterable, List

from dedsec.core.module_contract import ModuleMetadata


_BUILTINS = [
    ModuleMetadata(
        "waf", "🛡️  WAF Detection", "web", "dedsec.modules.waf_detect",
        impact_class="active-safe", active=True, requires_target_http=True,
        protocols=["http"], produces=["technology", "filtering-observation"],
    ),
    ModuleMetadata(
        "tech", "🌐 Technology Fingerprinting", "web", "dedsec.modules.tech_fingerprint",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["technology"],
    ),
    ModuleMetadata(
        "dns", "🔍 DNS Reconnaissance", "network", "dedsec.modules.dns_recon",
        impact_class="active-safe", active=True, protocols=["dns"],
        produces=["dns-record", "host", "ip", "email-posture"],
    ),
    ModuleMetadata(
        "geo", "🌍 IP & GeoLocation", "network", "dedsec.modules.ip_geo",
        impact_class="passive", protocols=["dns", "external-intelligence"], produces=["ip-context"],
    ),
    ModuleMetadata(
        "ssl", "🔒 SSL/TLS Analysis", "network", "dedsec.modules.ssl_analysis",
        impact_class="active-safe", active=True, protocols=["tls"],
        produces=["certificate", "tls-posture"],
    ),
    ModuleMetadata(
        "headers", "📋 HTTP Header Audit", "web", "dedsec.modules.header_audit",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["header-posture"],
    ),
    ModuleMetadata(
        "redirect", "🚪 Open Redirect Check", "web", "dedsec.modules.open_redirect",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["http"],
        produces=["redirect-candidate"],
    ),
    ModuleMetadata(
        "robots", "🤖 Robots & Sitemap", "discovery", "dedsec.modules.robots_sitemap",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["url", "endpoint"],
    ),
    ModuleMetadata(
        "cookies", "🍪 Cookie Audit", "web", "dedsec.modules.cookie_audit",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["cookie-posture"],
    ),
    ModuleMetadata(
        "ports", "📡 Port Exposure Scan", "network", "dedsec.modules.port_scan",
        impact_class="active-safe", active=True, protocols=["tcp", "http"],
        produces=["service", "port-state"],
    ),
    ModuleMetadata(
        "whois", "🕵️  WHOIS Lookup", "network", "dedsec.modules.whois_lookup",
        impact_class="passive", protocols=["whois"], produces=["registration-context"],
    ),
    ModuleMetadata(
        "subdomains", "🌐 Subdomain Enumeration", "discovery", "dedsec.modules.subdomain_enum",
        impact_class="active-safe", active=True, protocols=["dns", "http", "external-intelligence"],
        produces=["host", "ip", "url"],
    ),
    ModuleMetadata(
        "js", "📜 JS & Endpoint Extraction", "discovery", "dedsec.modules.js_extraction",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["url", "endpoint", "secret-candidate"],
    ),
    ModuleMetadata(
        "hosting", "🏢 Hosting Intelligence", "network", "dedsec.modules.hosting_intel",
        impact_class="normal", protocols=["dns", "http", "external-intelligence"],
        produces=["ip", "provider-context"],
    ),
    ModuleMetadata(
        "exposures", "🚨 Common Exposure Checks", "web", "dedsec.modules.exposure_checks",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["http"],
        produces=["exposure-candidate", "verified-exposure"],
    ),
    ModuleMetadata(
        "cors", "🌐 CORS Configuration Check", "web", "dedsec.modules.cors_check",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["http"],
        produces=["cors-candidate"],
    ),
    ModuleMetadata(
        "csp", "🛡️  CSP Deep Analyzer", "web", "dedsec.modules.csp_analyzer",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["csp-posture"],
    ),
    ModuleMetadata(
        "ratelimit", "📡 Rate Limit Observation", "web", "dedsec.modules.rate_limit_check",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["http"],
        produces=["rate-limit-observation"],
    ),
    ModuleMetadata(
        "clickjacking", "🖼️  Clickjacking Framing Posture", "web", "dedsec.modules.clickjacking_check",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["framing-posture"],
    ),
    ModuleMetadata(
        "email", "✉️  Email Security Audit", "network", "dedsec.modules.email_security",
        impact_class="passive", protocols=["dns"], produces=["email-posture"],
    ),
    ModuleMetadata(
        "vhost", "🖥️  Virtual Host Candidate Finder", "discovery", "dedsec.modules.vhost_finder",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["dns", "http"],
        produces=["host-candidate"],
    ),
    ModuleMetadata(
        "api_schema", "📜 API & OpenAPI Schema Scanner", "discovery", "dedsec.modules.api_schema_scanner",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["api-schema", "endpoint"],
    ),
    ModuleMetadata(
        "http_methods", "🛠️  HTTP Methods Audit", "web", "dedsec.modules.http_methods_audit",
        impact_class="active-safe", active=True, requires_target_http=True, protocols=["http"],
        produces=["method-posture"],
    ),
    ModuleMetadata(
        "security_policy", "📄 Security Policy Audit", "discovery", "dedsec.modules.security_policy_audit",
        impact_class="normal", requires_target_http=True, protocols=["http"],
        produces=["policy-surface"],
    ),
]

MODULES: Dict[str, ModuleMetadata] = {item.key: item for item in _BUILTINS}


def module_map() -> Dict[str, tuple]:
    return {
        key: (metadata.import_path, metadata.display_name)
        for key, metadata in MODULES.items()
        if metadata.import_path
    }


def get_module(key: str) -> ModuleMetadata:
    try:
        return MODULES[key]
    except KeyError:
        raise KeyError("Unknown DEDSEC module: %s" % key)


def validate_impact(keys: Iterable[str], maximum_impact: str) -> List[str]:
    from dedsec.core.scan_plan import impact_allowed

    blocked = []
    for key in keys:
        metadata = get_module(key)
        if not impact_allowed(metadata.impact_class, maximum_impact):
            blocked.append(key)
    return blocked


def keys() -> List[str]:
    return list(MODULES.keys())
