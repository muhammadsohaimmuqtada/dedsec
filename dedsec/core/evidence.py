import hashlib
import json
import os
import re
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dedsec.core.contracts import ModuleResult

_SECRET_KEYS = re.compile(
    r"(^|_)(authorization|cookie|set_cookie|password|passwd|secret|token|api_?key|session|private_?key)($|_)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def strip_ansi(value: str) -> str:
    return _ANSI_ESCAPE.sub("", value or "")


def redact_text(value: str) -> str:
    value = strip_ansi(value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    return _ASSIGNMENT.sub(lambda match: "%s=[REDACTED]" % match.group(1), value)


def redact_value(value: Any, key: Optional[str] = None) -> Any:
    if key and _SECRET_KEYS.search(key.replace("-", "_")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    scan_id: str
    module: str
    label: str
    status: str
    observed_at: str
    sha256: str
    data: Dict[str, Any]
    error: Optional[str]
    output_excerpt: str
    artifact_path: Optional[str] = None


class EvidenceStore:
    """Thread-safe, model-independent evidence persistence for one scan."""

    def __init__(self, scan_id: Optional[str] = None, artifact_dir: Optional[str] = None):
        self.scan_id = scan_id or "scan-%s" % uuid.uuid4().hex[:12]
        self.artifact_dir = Path(artifact_dir).expanduser() if artifact_dir else None
        self._records: Dict[str, EvidenceRecord] = {}
        self._lock = threading.RLock()
        if self.artifact_dir:
            self.artifact_dir.mkdir(parents=True, exist_ok=True)

    def persist_module_result(self, result: ModuleResult) -> EvidenceRecord:
        observed_at = _utc_now()
        raw_payload = {
            "module": result.module,
            "label": result.label,
            "status": result.status,
            "data": result.data,
            "error": result.error,
            # Terminal color control sequences are presentation metadata, not evidence.
            "output": strip_ansi(result.output or ""),
            "attempts": result.attempts,
            "failure_class": result.failure_class,
        }
        digest = hashlib.sha256(_json_bytes(raw_payload)).hexdigest()
        evidence_id = "ev-%s" % hashlib.sha256(
            (self.scan_id + ":" + result.module + ":" + digest).encode("utf-8")
        ).hexdigest()[:16]

        redacted_data = redact_value(result.data)
        redacted_error = redact_text(result.error) if result.error else None
        redacted_output = redact_text(result.output or "")[:2000]

        record = EvidenceRecord(
            evidence_id=evidence_id,
            scan_id=self.scan_id,
            module=result.module,
            label=result.label,
            status=result.status,
            observed_at=observed_at,
            sha256=digest,
            data=redacted_data if isinstance(redacted_data, dict) else {},
            error=redacted_error,
            output_excerpt=redacted_output,
            artifact_path=None,
        )

        with self._lock:
            if self.artifact_dir:
                artifact_path = self._write_artifact(record)
                record = EvidenceRecord(**dict(asdict(record), artifact_path=artifact_path))
            self._records[evidence_id] = record
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        with self._lock:
            return self._records.get(evidence_id)

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                asdict(item)
                for item in sorted(self._records.values(), key=lambda item: item.evidence_id)
            ]

    def _write_artifact(self, record: EvidenceRecord) -> str:
        assert self.artifact_dir is not None
        safe_module = re.sub(r"[^A-Za-z0-9_.-]", "_", record.module)
        destination = self.artifact_dir / ("%s-%s.json" % (safe_module, record.evidence_id))
        payload = asdict(record)
        fd, temp_name = tempfile.mkstemp(
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=str(self.artifact_dir),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, destination)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return str(destination)
