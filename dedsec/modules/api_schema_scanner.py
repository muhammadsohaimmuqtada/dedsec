from urllib.parse import urljoin

from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section

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
HTTP_METHOD_KEYS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def run(url, domain, timeout=10):
    section("API & OpenAPI Schema Scanner", "📜")
    results = {"schemas_found": [], "endpoints_extracted": [], "transport_failures": 0}
    schemas = []
    endpoints = {}

    for path in SCHEMA_PATHS:
        target = urljoin(url, path)
        response = safe_request(target, timeout=timeout, allow_redirects=False)
        if response is None:
            results["transport_failures"] += 1
            continue
        if response.status_code != 200:
            continue

        try:
            data = response.json()
        except Exception:
            data = None

        if isinstance(data, dict) and (
            "openapi" in data or "swagger" in data or isinstance(data.get("paths"), dict)
        ):
            version = data.get("openapi") or data.get("swagger") or "Unknown"
            schemas.append(
                {
                    "url": target,
                    "type": "OpenAPI/Swagger",
                    "version": version,
                    "title": data.get("info", {}).get("title", "API Schema"),
                    "classification": "surface-observation",
                }
            )
            for endpoint, methods in data.get("paths", {}).items():
                if not isinstance(methods, dict):
                    continue
                method_names = sorted(
                    key.upper() for key in methods if key.lower() in HTTP_METHOD_KEYS
                )
                existing = endpoints.setdefault(endpoint, set())
                existing.update(method_names)
            continue

        body = (response.text or "")[:10000].lower()
        content_type = response.headers.get("Content-Type", "").lower()
        if "swagger-ui" in body or "swagger ui" in body:
            schemas.append(
                {
                    "url": target,
                    "type": "Swagger UI HTML",
                    "version": "HTML",
                    "classification": "surface-observation",
                }
            )
        elif path == "/graphql" and (
            "graphql" in body or "application/graphql" in content_type
        ):
            schemas.append(
                {
                    "url": target,
                    "type": "GraphQL candidate",
                    "version": None,
                    "classification": "surface-observation",
                }
            )

    # URL is part of the schema identity, while endpoints are globally deduped.
    seen_schema = set()
    deduped_schemas = []
    for schema in schemas:
        key = (schema["url"], schema["type"], schema.get("version"))
        if key not in seen_schema:
            seen_schema.add(key)
            deduped_schemas.append(schema)

    extracted = [
        {"endpoint": endpoint, "methods": sorted(methods)}
        for endpoint, methods in sorted(endpoints.items())
    ]
    results["schemas_found"] = deduped_schemas
    results["endpoints_extracted"] = extracted

    if deduped_schemas:
        print(f"\n{Colors.GREEN}[+]{Colors.RESET} {Colors.BOLD}Public API Schema Surfaces:{Colors.RESET}")
        for schema in deduped_schemas:
            info(schema["type"], schema["url"])
    if extracted:
        info("Unique API Endpoints Mapped", str(len(extracted)))
        for endpoint in extracted[:15]:
            print(f"       {Colors.CYAN}• {endpoint['endpoint']} [{', '.join(endpoint['methods'])}]{Colors.RESET}")
    elif not deduped_schemas:
        info("API Schema Audit", f"{Colors.DIM}No public OpenAPI / Swagger schema detected.{Colors.RESET}")
    return results
