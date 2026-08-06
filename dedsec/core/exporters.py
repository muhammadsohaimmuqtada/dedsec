import csv
import html
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List


def _atomic_text(path: str, text: str) -> str:
    destination = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=os.path.basename(destination) + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return destination


def _findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    analysis = report.get("analysis") or {}
    findings: List[Dict[str, Any]] = []
    for item in analysis.get("verified_findings") or []:
        if isinstance(item, dict):
            entry = dict(item)
            entry.setdefault("confidence", "verified")
            entry.setdefault("classification", "verified-finding")
            findings.append(entry)
    for item in analysis.get("hypotheses") or []:
        if isinstance(item, dict):
            entry = dict(item)
            entry.setdefault("confidence", "hypothesis")
            entry.setdefault("classification", "hypothesis")
            findings.append(entry)
    return findings


def _csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula interpretation without altering report data."""
    text = "" if value is None else str(value)
    stripped = text.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _safe_basename(value: str) -> str:
    name = str(value or "").strip()
    if not name or name in {".", ".."}:
        raise ValueError("Export basename must be a non-empty file stem")
    if os.path.basename(name) != name or "/" in name or "\\" in name:
        raise ValueError("Export basename must not contain path separators")
    return name


def export_json(report: Dict[str, Any], path: str) -> str:
    return _atomic_text(path, json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")


def export_jsonl(report: Dict[str, Any], path: str) -> str:
    records: List[Dict[str, Any]] = []
    for item in report.get("modules") or []:
        records.append({"record_type": "module", **dict(item)})
    for item in _findings(report):
        records.append({"record_type": "finding", **item})
    workspace = report.get("workspace") or {}
    for item in workspace.get("assets") or []:
        records.append({"record_type": "asset", **dict(item)})
    for item in workspace.get("requests") or []:
        records.append({"record_type": "request", **dict(item)})
    text = "".join(json.dumps(item, sort_keys=True, default=str) + "\n" for item in records)
    return _atomic_text(path, text)


def _sarif_level(severity: str) -> str:
    value = (severity or "INFO").upper()
    if value in {"CRITICAL", "HIGH"}:
        return "error"
    if value in {"MEDIUM", "LOW"}:
        return "warning"
    return "note"


def export_sarif(report: Dict[str, Any], path: str) -> str:
    results = []
    rules: Dict[str, Dict[str, Any]] = {}
    target = (report.get("target") or {}).get("url") or ""
    for index, finding in enumerate(_findings(report), start=1):
        rule_id = str(finding.get("id") or finding.get("type") or "DEDSEC-%04d" % index)
        title = str(finding.get("title") or finding.get("summary") or finding.get("type") or rule_id)
        severity = str(finding.get("severity") or "INFO")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": title[:120],
                "shortDescription": {"text": title},
                "properties": {"security-severity": severity},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(severity),
                "message": {"text": title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.get("url") or target)}
                        }
                    }
                ],
                "properties": {
                    "classification": finding.get("classification"),
                    "confidence": finding.get("confidence"),
                    "evidence_ids": finding.get("evidence_ids") or [],
                },
            }
        )
    payload = {
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
    return export_json(payload, path)


def export_csv(report: Dict[str, Any], path: str) -> str:
    destination = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(destination) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=os.path.basename(destination) + ".", suffix=".tmp", dir=directory)
    os.close(fd)
    try:
        with open(temp_name, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "classification",
                    "severity",
                    "confidence",
                    "title",
                    "url",
                    "module",
                    "evidence_ids",
                ],
            )
            writer.writeheader()
            target = (report.get("target") or {}).get("url") or ""
            for item in _findings(report):
                row = {
                    "classification": item.get("classification"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                    "title": item.get("title") or item.get("summary") or item.get("type"),
                    "url": item.get("url") or target,
                    "module": item.get("module"),
                    "evidence_ids": ";".join(item.get("evidence_ids") or []),
                }
                writer.writerow({key: _csv_cell(value) for key, value in row.items()})
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, destination)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return destination


def export_html(report: Dict[str, Any], path: str) -> str:
    target = report.get("target") or {}
    summary = report.get("summary") or {}
    workspace = report.get("workspace") or {}
    rows = []
    for item in _findings(report):
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (
                html.escape(str(item.get("classification") or "")),
                html.escape(str(item.get("severity") or "")),
                html.escape(str(item.get("confidence") or "")),
                html.escape(str(item.get("title") or item.get("summary") or item.get("type") or "")),
            )
        )
    page = """<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><title>DEDSEC report</title>
<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ccc;padding:.45rem;text-align:left}code{word-break:break-all}.muted{color:#666}</style></head><body>
<h1>DEDSEC scan report</h1>
<p><strong>Target:</strong> <code>%s</code></p>
<p><strong>Scan ID:</strong> <code>%s</code></p>
<p><strong>Schema:</strong> %s</p>
<h2>Summary</h2><pre>%s</pre>
<h2>Coverage</h2><pre>%s</pre>
<h2>Findings</h2><table><thead><tr><th>Classification</th><th>Severity</th><th>Confidence</th><th>Title</th></tr></thead><tbody>%s</tbody></table>
<p class=\"muted\">This report distinguishes observations, hypotheses, and verified findings. Absence of findings is not proof of absence when coverage is incomplete.</p>
</body></html>""" % (
        html.escape(str(target.get("url") or "")),
        html.escape(str(report.get("scan_id") or "")),
        html.escape(str(report.get("schema_version") or "")),
        html.escape(json.dumps(summary, indent=2, sort_keys=True, default=str)),
        html.escape(json.dumps(workspace.get("coverage") or {}, indent=2, sort_keys=True, default=str)),
        "".join(rows),
    )
    return _atomic_text(path, page)


def export_report(
    report: Dict[str, Any],
    directory: str,
    formats: Iterable[str],
    basename: str = "dedsec-report",
) -> Dict[str, str]:
    expanded = os.path.abspath(os.path.expanduser(directory))
    os.makedirs(expanded, exist_ok=True)
    safe_basename = _safe_basename(basename)
    outputs: Dict[str, str] = {}
    for raw_format in formats:
        format_name = str(raw_format).lower()
        if format_name == "json":
            outputs[format_name] = export_json(report, os.path.join(expanded, safe_basename + ".json"))
        elif format_name == "jsonl":
            outputs[format_name] = export_jsonl(report, os.path.join(expanded, safe_basename + ".jsonl"))
        elif format_name == "sarif":
            outputs[format_name] = export_sarif(report, os.path.join(expanded, safe_basename + ".sarif"))
        elif format_name == "csv":
            outputs[format_name] = export_csv(report, os.path.join(expanded, safe_basename + ".csv"))
        elif format_name == "html":
            outputs[format_name] = export_html(report, os.path.join(expanded, safe_basename + ".html"))
        else:
            raise ValueError("Unsupported export format: %s" % format_name)
    return outputs
