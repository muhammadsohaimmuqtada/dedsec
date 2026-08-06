import csv
import html
import json
import os
import re
import tempfile
from typing import Any, Dict, Iterable, List, Sequence

from dedsec.core.evidence import redact_value


_SUPPORTED = {"json", "jsonl", "sarif", "csv", "html"}
_SAFE_BASENAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_basename(value: str) -> str:
    safe = _SAFE_BASENAME_RE.sub("-", str(value or "dedsec-report")).strip(".-")
    return safe[:120] or "dedsec-report"


def _atomic_text(path: str, text: str) -> None:
    destination = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=os.path.basename(destination) + ".",
        suffix=".tmp",
        dir=directory,
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _finding_rows(report: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    analysis = report.get("analysis") or {}
    for classification, key in (
        ("verified-finding", "verified_findings"),
        ("hypothesis", "hypotheses"),
        ("rejected-or-unverified", "rejected_or_unverified"),
    ):
        for item in analysis.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            yield {
                "classification": classification,
                "id": item.get("id") or "",
                "title": item.get("title") or item.get("name") or item.get("type") or key,
                "severity": str(item.get("severity") or "INFO").upper(),
                "confidence": item.get("confidence") or "",
                "source": item.get("source") or item.get("module") or "",
                "url": item.get("url") or item.get("target") or "",
                "parameter": item.get("parameter") or item.get("param") or "",
            }


def _jsonl_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = [
        {
            "type": "scan",
            "schema_version": report.get("schema_version"),
            "scan_id": report.get("scan_id"),
            "target": report.get("target"),
            "summary": report.get("summary"),
        }
    ]
    for module in report.get("modules", []) or []:
        records.append({"type": "module", "data": module})
    for finding in _finding_rows(report):
        records.append({"type": "finding", "data": finding})
    workspace = report.get("workspace") or {}
    for key, item_type in (
        ("assets", "asset"),
        ("requests", "request"),
        ("observations", "observation"),
    ):
        for item in workspace.get(key, []) or []:
            records.append({"type": item_type, "data": item})
    return records


def _sarif_level(severity: str) -> str:
    severity = (severity or "INFO").upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity in {"MEDIUM", "LOW"}:
        return "warning"
    return "note"


def _sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        row
        for row in _finding_rows(report)
        if row["classification"] in {"verified-finding", "hypothesis"}
    ]
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for index, row in enumerate(rows, start=1):
        rule_id = str(row["id"] or "dedsec-%d" % index)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(row["title"])[:120],
                "shortDescription": {"text": str(row["title"])},
                "properties": {
                    "severity": row["severity"],
                    "classification": row["classification"],
                    "source": row["source"],
                },
            },
        )
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(row["severity"]),
            "message": {"text": str(row["title"])},
            "properties": {
                "classification": row["classification"],
                "confidence": row["confidence"],
                "parameter": row["parameter"],
            },
        }
        if row["url"]:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(row["url"])}
                    }
                }
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DEDSEC",
                        "informationUri": "https://github.com/muhammadsohaimmuqtada/dedsec",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }


def _csv_text(report: Dict[str, Any]) -> str:
    import io

    buffer = io.StringIO(newline="")
    fieldnames = [
        "classification",
        "id",
        "title",
        "severity",
        "confidence",
        "source",
        "url",
        "parameter",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in _finding_rows(report):
        writer.writerow({key: row.get(key, "") for key in fieldnames})
    return buffer.getvalue()


def _html_report(report: Dict[str, Any]) -> str:
    target = report.get("target") or {}
    summary = report.get("summary") or {}
    rows = list(_finding_rows(report))
    coverage = (report.get("workspace") or {}).get("coverage") or {}

    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value), quote=True)

    finding_rows = "".join(
        "<tr>"
        "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
        "</tr>"
        % (
            esc(row["classification"]),
            esc(row["severity"]),
            esc(row["title"]),
            esc(row["source"]),
            esc(row["url"]),
        )
        for row in rows
    )
    if not finding_rows:
        finding_rows = '<tr><td colspan="5">No correlated findings/hypotheses in this report.</td></tr>'

    raw_json = html.escape(
        json.dumps(report, indent=2, sort_keys=True, default=str),
        quote=False,
    )
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DEDSEC report</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#171717;background:#fff}
h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #d4d4d4;padding:.5rem;text-align:left;vertical-align:top}th{background:#f5f5f5}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f5f5;padding:1rem;border:1px solid #ddd}.metric{display:inline-block;margin:.25rem 1rem .25rem 0}.muted{color:#666}
</style>
</head>
<body>
<h1>DEDSEC scan report</h1>
<p><strong>Target:</strong> %s<br><strong>Domain:</strong> %s<br><strong>Scan ID:</strong> %s<br><strong>Schema:</strong> %s</p>
<h2>Summary</h2>
<p><span class="metric">Verified: <strong>%s</strong></span><span class="metric">Hypotheses: <strong>%s</strong></span><span class="metric">Assets: <strong>%s</strong></span><span class="metric">Requests discovered: <strong>%s</strong></span><span class="metric">Insertion points: <strong>%s</strong></span></p>
<p class="muted">Coverage must be considered when interpreting zero findings. A partial scan is not proof that a target is vulnerability-free.</p>
<h2>Findings and hypotheses</h2>
<table><thead><tr><th>Class</th><th>Severity</th><th>Title</th><th>Source</th><th>URL</th></tr></thead><tbody>%s</tbody></table>
<h2>Coverage</h2>
<pre>%s</pre>
<h2>Canonical JSON</h2>
<pre>%s</pre>
</body>
</html>
""" % (
        esc(target.get("url")),
        esc(target.get("domain")),
        esc(report.get("scan_id")),
        esc(report.get("schema_version")),
        esc(summary.get("verified_findings", 0)),
        esc(summary.get("hypotheses", 0)),
        esc(summary.get("assets", 0)),
        esc(summary.get("requests_discovered", 0)),
        esc(summary.get("insertion_points_discovered", 0)),
        finding_rows,
        html.escape(json.dumps(coverage, indent=2, sort_keys=True, default=str), quote=False),
        raw_json,
    )


def export_report(
    report: Dict[str, Any],
    directory: str,
    formats: Sequence[str],
    basename: str = "dedsec-report",
) -> Dict[str, str]:
    safe_report = redact_value(report)
    requested = []
    for value in formats:
        fmt = str(value).strip().lower()
        if not fmt:
            continue
        if fmt not in _SUPPORTED:
            raise ValueError("Unsupported report format: %s" % fmt)
        if fmt not in requested:
            requested.append(fmt)
    root = os.path.abspath(os.path.expanduser(directory))
    os.makedirs(root, exist_ok=True)
    base = _safe_basename(basename)
    outputs: Dict[str, str] = {}

    for fmt in requested:
        path = os.path.join(root, "%s.%s" % (base, fmt))
        if fmt == "json":
            text = json.dumps(safe_report, indent=2, sort_keys=True, default=str) + "\n"
        elif fmt == "jsonl":
            text = "".join(
                json.dumps(item, sort_keys=True, default=str) + "\n"
                for item in _jsonl_records(safe_report)
            )
        elif fmt == "sarif":
            text = json.dumps(_sarif(safe_report), indent=2, sort_keys=True, default=str) + "\n"
        elif fmt == "csv":
            text = _csv_text(safe_report)
        else:
            text = _html_report(safe_report)
        _atomic_text(path, text)
        outputs[fmt] = path
    return outputs
