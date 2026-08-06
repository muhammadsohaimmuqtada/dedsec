from dedsec.core.colors import Colors
from dedsec.core.utils import info, safe_request, section, warn

DECLARED_SENSITIVE_METHODS = {"PUT", "DELETE", "CONNECT", "PATCH"}


def _parse_methods(value):
    if not value:
        return []
    return sorted({item.strip().upper() for item in value.split(",") if item.strip()})


def run(url, domain, timeout=10):
    section("HTTP Methods Audit", "🛠️")
    results = {
        "allow_header": None,
        "declared_methods": [],
        "allowed_methods": [],
        "observations": [],
        "risks": [],
        "transport_failures": 0,
    }

    options_response = safe_request(
        url,
        timeout=timeout,
        method="OPTIONS",
        allow_redirects=False,
        cache=False,
    )
    if options_response is None:
        results["transport_failures"] += 1
    else:
        allow_header = (
            options_response.headers.get("Allow")
            or options_response.headers.get("Access-Control-Allow-Methods")
        )
        results["allow_header"] = allow_header
        declared = _parse_methods(allow_header)
        results["declared_methods"] = declared
        if allow_header:
            info("Declared Methods", allow_header)
        sensitive = sorted(set(declared) & DECLARED_SENSITIVE_METHODS)
        if sensitive:
            results["observations"].append(
                {
                    "type": "declared-methods",
                    "methods": sensitive,
                    "note": "Method declaration alone does not demonstrate unauthorized state change.",
                }
            )
            warn(
                "Potentially state-changing methods are declared: "
                + ", ".join(sensitive)
                + " (observation only)"
            )

    # TRACE is non-state-changing and can be validated without attempting PUT or
    # DELETE against a live application. Claim XST only when the server echoes the
    # TRACE request, rather than from HTTP 200 alone.
    trace_response = safe_request(
        url,
        timeout=timeout,
        method="TRACE",
        allow_redirects=False,
        headers={"X-DEDSEC-Trace-Probe": "1"},
        cache=False,
    )
    if trace_response is None:
        results["transport_failures"] += 1
    else:
        body = trace_response.text or ""
        echoed = (
            trace_response.status_code == 200
            and ("TRACE " in body.upper() or "X-DEDSEC-TRACE-PROBE" in body.upper())
        )
        if trace_response.status_code not in {400, 403, 405, 501}:
            results["allowed_methods"].append(
                {"method": "TRACE", "status": trace_response.status_code, "echoed": echoed}
            )
        if echoed:
            results["risks"].append("HTTP TRACE echoes request data (XST-capable behavior)")
            warn("HTTP TRACE echoed request data; XST-capable behavior observed.")
        elif trace_response.status_code == 200:
            results["observations"].append(
                {
                    "type": "trace-response",
                    "status": 200,
                    "note": "TRACE returned 200 but request echo was not observed; XST is not confirmed.",
                }
            )

    if not results["risks"] and not results["observations"]:
        info("HTTP Methods Audit", f"{Colors.GREEN}No supported dangerous-method signal observed.{Colors.RESET}")
    return results
