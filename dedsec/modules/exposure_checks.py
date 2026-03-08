from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

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
]


def _body_excerpt(resp, limit=300):
    text = resp.text if isinstance(resp.text, str) else ""
    return text[:limit].replace("\n", " ").strip().lower()


def _matches_json_keys(resp, keys):
    try:
        data = resp.json()
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    return all(key in data for key in keys)


def _is_confirmed(resp, check):
    if resp.status_code not in check["status_in"]:
        return False, "unexpected status"

    if check.get("json_keys"):
        if _matches_json_keys(resp, check["json_keys"]):
            return True, "expected JSON keys found"
        return False, "expected JSON keys missing"

    if check.get("binary_ok"):
        content_type = resp.headers.get("Content-Type", "").lower()
        if "application/octet-stream" in content_type or "application/x-java-serialized-object" in content_type:
            return True, f"binary content-type '{content_type}'"

    excerpt = _body_excerpt(resp)
    indicators = check.get("content_indicators", [])
    if all(indicator in excerpt for indicator in indicators[:1]) and any(indicator in excerpt for indicator in indicators):
        return True, "strong body indicator match"
    return False, "content signature mismatch"


def run(url, domain, timeout=10):
    section("Common Exposure Checks", "🚨")
    results = {"confirmed": [], "candidates": [], "tested": 0}

    for check in CHECKS:
        test_url = f"{url.rstrip('/')}{check['path']}"
        resp = safe_request(test_url, timeout=timeout, allow_redirects=False)
        results["tested"] += 1

        if not resp:
            print(f"{Colors.DIM}[ ] {check['label']}: request failed{Colors.RESET}")
            continue

        confirmed, reason = _is_confirmed(resp, check)
        finding = {
            "id": check["id"],
            "label": check["label"],
            "severity": check["severity"],
            "url": test_url,
            "status": resp.status_code,
            "evidence": reason,
        }

        if confirmed:
            warn(f"CONFIRMED {check['severity']}: {check['label']} ({test_url})")
            results["confirmed"].append(finding)
        elif resp.status_code in {200, 401, 403}:
            print(f"{Colors.DIM}[~] candidate: {check['label']} ({resp.status_code}){Colors.RESET}")
            results["candidates"].append(finding)
        else:
            print(f"{Colors.DIM}[ ] {check['label']}: {resp.status_code}{Colors.RESET}")

    if results["confirmed"]:
        info("Confirmed Exposures", str(len(results["confirmed"])))
    else:
        info("Confirmed Exposures", f"{Colors.GREEN}0{Colors.RESET}")

    if results["candidates"]:
        warn(f"{len(results['candidates'])} candidate endpoint(s) need manual validation.")

    return results
