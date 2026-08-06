import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dedsec.core.colors import Colors
from dedsec.core.contracts import ModuleResult
from dedsec.core.correlator import FindingsCorrelator
from dedsec.core.evidence import EvidenceStore, redact_value

REPORT_SCHEMA_VERSION = "2.1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _module_summary(module_results: List[ModuleResult]) -> Dict[str, int]:
    counts = {
        "total": len(module_results),
        "successful": 0,
        "partial": 0,
        "inconclusive": 0,
        "failed": 0,
        "timed_out": 0,
        "aborted": 0,
    }
    for item in module_results:
        if item.status == "success":
            counts["successful"] += 1
        elif item.status == "partial":
            counts["partial"] += 1
        elif item.status == "inconclusive":
            counts["inconclusive"] += 1
        elif item.status == "timeout":
            counts["timed_out"] += 1
        elif item.status == "aborted":
            counts["aborted"] += 1
        else:
            counts["failed"] += 1
    return counts


def build_report(
    url: str,
    domain: str,
    results: Dict[str, Any],
    module_results: Optional[List[ModuleResult]] = None,
    evidence_store: Optional[EvidenceStore] = None,
    correlated: Optional[Dict[str, Any]] = None,
    runtime_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    modules = module_results or []
    correlation = correlated if correlated is not None else FindingsCorrelator().correlate(modules)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": evidence_store.scan_id if evidence_store else None,
        "generated_at": _utc_now(),
        "target": {"url": url, "domain": domain},
        "runtime": redact_value(runtime_metadata or {}),
        "summary": {
            **_module_summary(modules),
            "verified_findings": len(correlation.get("verified_findings", [])),
            "hypotheses": len(correlation.get("hypotheses", [])),
            "attack_surface_score": correlation.get("attack_surface_score", 0),
        },
        "modules": [
            {
                "module": item.module,
                "label": item.label,
                "status": item.status,
                "duration": round(item.duration, 3),
                "attempts": item.attempts,
                "started_at": item.started_at,
                "error": redact_value(item.error),
                "failure_class": item.failure_class,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in modules
        ],
        "results": redact_value(results),
        "analysis": redact_value(correlation),
        "evidence": evidence_store.snapshot() if evidence_store else [],
    }


def _write_json_atomic(path: str, payload: Dict[str, Any]) -> None:
    destination = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=os.path.basename(destination) + ".",
        suffix=".tmp",
        dir=directory,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def generate_report(
    url,
    domain,
    results,
    json_output=False,
    output_file=None,
    module_results=None,
    evidence_store=None,
    correlated=None,
    runtime_metadata=None,
):
    report_data = build_report(
        url=url,
        domain=domain,
        results=results,
        module_results=module_results,
        evidence_store=evidence_store,
        correlated=correlated,
        runtime_metadata=runtime_metadata,
    )
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}  DEDSEC SCAN COMPLETE{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Target:    {url}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Domain:    {domain}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Timestamp: {timestamp}")
    print(f"{Colors.GREEN}[+]{Colors.RESET} Modules:   {report_data['summary']['total']} terminal")
    print(
        f"{Colors.GREEN}[+]{Colors.RESET} Status:    "
        f"{report_data['summary']['successful']} success | "
        f"{report_data['summary']['partial']} partial | "
        f"{report_data['summary']['inconclusive']} inconclusive | "
        f"{report_data['summary']['failed']} failed | "
        f"{report_data['summary']['timed_out']} timeout | "
        f"{report_data['summary']['aborted']} aborted"
    )
    print(
        f"{Colors.GREEN}[+]{Colors.RESET} Findings:  "
        f"{report_data['summary']['verified_findings']} verified | "
        f"{report_data['summary']['hypotheses']} hypotheses"
    )
    runtime = report_data.get("runtime", {})
    if "target_http_requests_used" in runtime:
        print(
            f"{Colors.GREEN}[+]{Colors.RESET} Target HTTP requests: "
            f"{runtime['target_http_requests_used']} / {runtime.get('target_http_request_budget', 'unbounded')}"
        )
    health = runtime.get("target_health", {})
    if health:
        print(
            f"{Colors.GREEN}[+]{Colors.RESET} Target health: "
            f"{health.get('state', 'unknown')}"
        )
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    if json_output:
        print(json.dumps(report_data, indent=2, default=str, sort_keys=True))
    if output_file:
        _write_json_atomic(output_file, report_data)
        print(f"{Colors.GREEN}[+]{Colors.RESET} Report saved to: {output_file}")
    return report_data
