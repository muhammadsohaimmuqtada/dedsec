from urllib.parse import urljoin
from dedsec.core.colors import Colors
from dedsec.core.utils import safe_request, section, info, warn, error

SCHEMA_PATHS = [
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/graphql",
]

def run(url, domain, timeout=10):
    section("API & OpenAPI Schema Scanner", "📜")
    results = {"schemas_found": [], "endpoints_extracted": []}

    discovered_schemas = []
    extracted_endpoints = []

    for path in SCHEMA_PATHS:
        target = urljoin(url, path)
        resp = safe_request(target, timeout=timeout)
        if not resp or resp.status_code != 200:
            continue

        # Try parsing JSON schema
        try:
            data = resp.json()
            if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                version = data.get("openapi") or data.get("swagger") or "Unknown"
                title = data.get("info", {}).get("title", "API Schema")
                
                schema_info = {"url": target, "type": "OpenAPI/Swagger", "version": version, "title": title}
                discovered_schemas.append(schema_info)
                
                # Parse paths and methods
                paths = data.get("paths", {})
                for ep, methods in paths.items():
                    if isinstance(methods, dict):
                        m_list = [m.upper() for m in methods.keys()]
                        extracted_endpoints.append({"endpoint": ep, "methods": m_list})
        except Exception:
            # Check if Swagger UI HTML
            if "swagger" in resp.text.lower() or "swagger-ui" in resp.text.lower():
                discovered_schemas.append({"url": target, "type": "Swagger UI HTML", "version": "HTML"})

    results["schemas_found"] = discovered_schemas
    results["endpoints_extracted"] = extracted_endpoints

    if discovered_schemas:
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}API Schemas Found:{Colors.RESET}")
        for s in discovered_schemas:
            warn(f"CONFIRMED SCHEMA: {s['type']} ({s.get('version', '')}) at {s['url']}")

    if extracted_endpoints:
        info("API Endpoints Mapped from Schema", str(len(extracted_endpoints)))
        for ep in extracted_endpoints[:15]:
            print(f"       {Colors.CYAN}\u2022 {ep['endpoint']} [{', '.join(ep['methods'])}]{Colors.RESET}")
        if len(extracted_endpoints) > 15:
            print(f"       {Colors.DIM}... and {len(extracted_endpoints) - 15} more endpoints{Colors.RESET}")
    elif not discovered_schemas:
        info("API Schema Audit", f"{Colors.DIM}No public OpenAPI / Swagger schemas detected.{Colors.RESET}")

    return results
