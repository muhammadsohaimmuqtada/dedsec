from dedsec.core.colors import Colors
from dedsec.core.utils import get_soft404_profile, info, is_soft_404, safe_request, section, warn

CHECKS = [
    {
        "id": "dotenv",
        "label": ".env file exposure",
        "path": "/.env",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["db_password=", "app_key=", "aws_access_key_id=", "secret_key=", "database_url="],
    },
    {
        "id": "dotenv_local",
        "label": ".env.local file exposure",
        "path": "/.env.local",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["db_password=", "app_key=", "secret_key="],
    },
    {
        "id": "dotenv_production",
        "label": ".env.production file exposure",
        "path": "/.env.production",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["db_password=", "app_key=", "secret_key="],
    },
    {
        "id": "dotenv_development",
        "label": ".env.development file exposure",
        "path": "/.env.development",
        "severity": "HIGH",
        "status_in": {200},
        "content_indicators": ["db_password=", "app_key=", "secret_key="],
    },
    {
        "id": "phpinfo",
        "label": "phpinfo() exposure",
        "path": "/phpinfo.php",
        "severity": "HIGH",
        "status_in": {200},
        "content_indicators": ["<title>phpinfo()", "php version"],
    },
    {
        "id": "apache_status",
        "label": "Apache server-status exposure",
        "path": "/server-status",
        "severity": "HIGH",
        "status_in": {200},
        "content_indicators": ["apache server status for", "server version:"],
    },
    {
        "id": "spring_actuator_env",
        "label": "Spring actuator env exposure",
        "path": "/actuator/env",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ['"propertysources"', '"activeprofiles"'],
    },
    {
        "id": "spring_actuator_heapdump",
        "label": "Spring actuator heapdump exposure",
        "path": "/actuator/heapdump",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["java", "heapdump", "hprof"],
        "binary_ok": True,
    },
    {
        "id": "docker_api",
        "label": "Docker API exposure",
        "path": "/version",
        "severity": "CRITICAL",
        "status_in": {200},
        "json_keys": ["Version", "ApiVersion", "MinAPIVersion"],
    },
    {
        "id": "git_head",
        "label": "Git HEAD exposure",
        "path": "/.git/HEAD",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["ref: refs/"],
    },
    {
        "id": "git_config",
        "label": "Git config exposure",
        "path": "/.git/config",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["[core]"],
    },
    {
        "id": "git_index",
        "label": "Git index exposure",
        "path": "/.git/index",
        "severity": "CRITICAL",
        "status_in": {200},
        "binary_magic": b"DIRC",
    },
    {
        "id": "svn_entries",
        "label": "SVN entries exposure",
        "path": "/.svn/entries",
        "severity": "HIGH",
        "status_in": {200},
        "content_indicators": ["svn"],
    },
    {
        "id": "config_json",
        "label": "config.json exposure",
        "path": "/config.json",
        "severity": "HIGH",
        "status_in": {200},
        "json_keys": [],
        "json_only": True,
    },
    {
        "id": "config_yml",
        "label": "config.yml exposure",
        "path": "/config.yml",
        "severity": "HIGH",
        "status_in": {200},
        "content_indicators": [":"],
    },
    {
        "id": "backup_zip",
        "label": "backup.zip exposure",
        "path": "/backup.zip",
        "severity": "HIGH",
        "status_in": {200},
        "binary_magic": b"PK\x03\x04",
    },
    {
        "id": "db_sql",
        "label": "db.sql exposure",
        "path": "/db.sql",
        "severity": "CRITICAL",
        "status_in": {200},
        "content_indicators": ["create table", "insert into"],
    },
    {
        "id": "swagger_ui",
        "label": "Swagger UI presence",
        "path": "/swagger-ui.html",
        "severity": "INFO",
        "status_in": {200},
        "content_indicators": ["swagger-ui", "swagger"],
        "observation_only": True,
    },
    {
        "id": "openapi_json",
        "label": "OpenAPI JSON presence",
        "path": "/openapi.json",
        "severity": "INFO",
        "status_in": {200},
        "json_keys": ["openapi", "paths"],
        "observation_only": True,
    },
    {
        "id": "security_txt",
        "label": "security.txt present",
        "path": "/.well-known/security.txt",
        "severity": "INFO",
        "status_in": {200},
        "content_indicators": ["contact:"],
        "observation_only": True,
    },
    {
        "id": "crossdomain",
        "label": "crossdomain.xml presence",
        "path": "/crossdomain.xml",
        "severity": "INFO",
        "status_in": {200},
        "content_indicators": ["<allow-access-from"],
        "observation_only": True,
    },
    {
        "id": "admin_panel",
        "label": "Admin panel presence",
        "path": "/admin/",
        "severity": "INFO",
        "status_in": {200, 301, 302, 401, 403},
        "observation_only": True,
        "content_indicators": ["admin", "administrator", "login", "dashboard"],
    },
    {
        "id": "wp_login",
        "label": "WordPress login presence",
        "path": "/wp-login.php",
        "severity": "INFO",
        "status_in": {200},
        "content_indicators": ["wp-submit", "user_login"],
        "observation_only": True,
    },
]


def _body_excerpt(resp, limit=1500):
    text = resp.text if isinstance(resp.text, str) else ""
    return text[:limit].replace("\n", " ").strip().lower()


def _matches_json_keys(resp, keys):
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    if not keys:
        return True
    return all(key in data for key in keys)


def _is_confirmed(resp, check, soft404_prof=None):
    if soft404_prof and is_soft_404(resp, soft404_prof):
        return False, "soft 404 response match"

    if resp.status_code not in check["status_in"]:
        return False, "unexpected status"

    if check.get("binary_magic"):
        content = resp.content if hasattr(resp, "content") else b""
        if content.startswith(check["binary_magic"]):
            return True, "binary magic bytes matched"
        return False, "binary magic bytes missing"

    if check.get("json_only") or check.get("json_keys"):
        if _matches_json_keys(resp, check.get("json_keys", [])):
            return True, "valid JSON keys/format confirmed"
        return False, "JSON validation failed"

    if check.get("binary_ok"):
        content_type = resp.headers.get("Content-Type", "").lower()
        if "application/octet-stream" in content_type or "application/x-java-serialized-object" in content_type:
            return True, f"binary content-type '{content_type}'"

    excerpt = _body_excerpt(resp)
    indicators = check.get("content_indicators", [])
    if not indicators:
        return True, "status matched"
    if any(indicator in excerpt for indicator in indicators):
        return True, "content signature match"
    return False, "content signature mismatch"


def run(url, domain, timeout=10):
    section("Common Exposure Checks", "🚨")
    results = {
        "confirmed": [],
        "observed": [],
        "candidates": [],
        "rejected": [],
        "transport_failures": 0,
        "tested": 0,
    }

    soft404_prof = get_soft404_profile(url, timeout=min(timeout, 5))
    if soft404_prof:
        info(
            "Soft-404 Baseline Profile",
            f"Status {soft404_prof.get('status_code')}, Avg Len ~{soft404_prof.get('avg_length')} bytes",
        )

    for check in CHECKS:
        test_url = f"{url.rstrip('/')}{check['path']}"
        resp = safe_request(test_url, timeout=timeout, allow_redirects=False)
        results["tested"] += 1

        if resp is None:
            results["transport_failures"] += 1
            print(f"{Colors.DIM}[ ] {check['label']}: transport failure{Colors.RESET}")
            continue

        confirmed, reason = _is_confirmed(resp, check, soft404_prof)
        finding = {
            "id": check["id"],
            "label": check["label"],
            "severity": check["severity"],
            "url": test_url,
            "status": resp.status_code,
            "evidence": reason,
        }

        if confirmed and check.get("observation_only"):
            finding["classification"] = "observation"
            results["observed"].append(finding)
            info(check["label"], f"observed at {test_url}")
        elif confirmed:
            finding["classification"] = "verified-sensitive-exposure"
            warn(f"CONFIRMED {check['severity']}: {check['label']} ({test_url})")
            results["confirmed"].append(finding)
        elif resp.status_code in {401, 403} and reason not in {
            "soft 404 response match",
            "content signature mismatch",
            "binary magic bytes missing",
            "JSON validation failed",
        }:
            finding["classification"] = "candidate"
            print(f"{Colors.DIM}[~] candidate: {check['label']} ({resp.status_code}){Colors.RESET}")
            results["candidates"].append(finding)
        else:
            finding["classification"] = "rejected"
            results["rejected"].append(finding)
            print(f"{Colors.DIM}[ ] {check['label']}: {resp.status_code} ({reason}){Colors.RESET}")

    info("Confirmed Sensitive Exposures", str(len(results["confirmed"])))
    if results["observed"]:
        info("Surface Observations", str(len(results["observed"])))
    if results["candidates"]:
        warn(f"{len(results['candidates'])} positive candidate endpoint(s) need manual validation.")
    if results["transport_failures"]:
        warn(f"{results['transport_failures']} probe(s) had transport failures; those paths are inconclusive.")

    return results
