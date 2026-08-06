import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dedsec.core.evidence import redact_value
from dedsec.core.workspace import ResearchWorkspace


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _loads(value: Optional[str], default):
    if not value:
        return default
    return json.loads(value)


class ProjectStore:
    """Redacted SQLite project history, checkpoints, resume, and workspace diff."""

    SCHEMA_VERSION = 1

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, timeout=30)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._initialize()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_checkpoint INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    workspace_json TEXT NOT NULL,
                    report_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scans_domain_updated
                    ON scans(domain, updated_at DESC);

                CREATE TABLE IF NOT EXISTS assets (
                    scan_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    kind TEXT,
                    entity_key TEXT,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, entity_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS edges (
                    scan_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    relation TEXT,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, entity_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS requests (
                    scan_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    method TEXT,
                    url TEXT,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, entity_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS observations (
                    scan_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    classification TEXT,
                    severity TEXT,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, entity_id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                """
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )

    @staticmethod
    def _safe_workspace(workspace: ResearchWorkspace) -> Dict[str, Any]:
        # ResearchWorkspace.snapshot() is already secret-aware; redact_value is
        # retained as a second persistence boundary for arbitrary metadata.
        return redact_value(workspace.snapshot())

    def _replace_entities(self, scan_id: str, snapshot: Dict[str, Any]) -> None:
        for table in ("assets", "edges", "requests", "observations"):
            self._connection.execute("DELETE FROM %s WHERE scan_id = ?" % table, (scan_id,))

        self._connection.executemany(
            "INSERT INTO assets(scan_id, entity_id, kind, entity_key, payload_json) "
            "VALUES(?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    str(item.get("id")),
                    item.get("kind"),
                    item.get("key"),
                    _json(item),
                )
                for item in snapshot.get("assets", [])
                if item.get("id")
            ],
        )
        self._connection.executemany(
            "INSERT INTO edges(scan_id, entity_id, relation, payload_json) VALUES(?, ?, ?, ?)",
            [
                (
                    scan_id,
                    str(item.get("id")),
                    item.get("relation"),
                    _json(item),
                )
                for item in snapshot.get("edges", [])
                if item.get("id")
            ],
        )
        self._connection.executemany(
            "INSERT INTO requests(scan_id, entity_id, method, url, payload_json) "
            "VALUES(?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    str(item.get("id")),
                    item.get("method"),
                    item.get("url"),
                    _json(item),
                )
                for item in snapshot.get("requests", [])
                if item.get("id")
            ],
        )
        self._connection.executemany(
            "INSERT INTO observations(scan_id, entity_id, classification, severity, payload_json) "
            "VALUES(?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    str(item.get("id")),
                    item.get("classification"),
                    item.get("severity"),
                    _json(item),
                )
                for item in snapshot.get("observations", [])
                if item.get("id")
            ],
        )

    def _save(
        self,
        workspace: ResearchWorkspace,
        status: str,
        report: Optional[Dict[str, Any]],
        checkpoint: bool,
    ) -> None:
        snapshot = self._safe_workspace(workspace)
        safe_report = redact_value(report) if report is not None else None
        now = _utc_now()
        target_url = str(snapshot.get("target_url") or "")
        domain = str(snapshot.get("domain") or workspace.domain)
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT created_at FROM scans WHERE scan_id = ?",
                (workspace.scan_id,),
            ).fetchone()
            created_at = existing["created_at"] if existing else now
            self._connection.execute(
                """
                INSERT INTO scans(
                    scan_id, domain, target_url, status, is_checkpoint,
                    created_at, updated_at, workspace_json, report_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    domain=excluded.domain,
                    target_url=excluded.target_url,
                    status=excluded.status,
                    is_checkpoint=excluded.is_checkpoint,
                    updated_at=excluded.updated_at,
                    workspace_json=excluded.workspace_json,
                    report_json=excluded.report_json
                """,
                (
                    workspace.scan_id,
                    domain,
                    target_url,
                    status,
                    1 if checkpoint else 0,
                    created_at,
                    now,
                    _json(snapshot),
                    _json(safe_report) if safe_report is not None else None,
                ),
            )
            self._replace_entities(workspace.scan_id, snapshot)

    def checkpoint(self, workspace: ResearchWorkspace) -> None:
        self._save(workspace, status="checkpoint", report=None, checkpoint=True)

    def save_workspace(
        self,
        workspace: ResearchWorkspace,
        status: str = "complete",
        report: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._save(
            workspace,
            status=status,
            report=report,
            checkpoint=status == "checkpoint",
        )

    def load_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._connection.execute(
                "SELECT workspace_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return _loads(row["workspace_json"], None) if row else None

    def load_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._connection.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return _loads(row["report_json"], None) if row else None

    def latest_checkpoint(self, domain: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT workspace_json
                FROM scans
                WHERE domain = ? AND status IN ('checkpoint', 'complete')
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                ((domain or "").lower().rstrip("."),),
            ).fetchone()
        return _loads(row["workspace_json"], None) if row else None

    def latest_scan(
        self,
        domain: str,
        exclude_scan_id: Optional[str] = None,
        complete_only: bool = True,
    ) -> Optional[Dict[str, Any]]:
        where = ["domain = ?"]
        params: List[Any] = [(domain or "").lower().rstrip(".")]
        if exclude_scan_id:
            where.append("scan_id <> ?")
            params.append(exclude_scan_id)
        if complete_only:
            where.append("status = 'complete'")
        query = (
            "SELECT scan_id, workspace_json, report_json, status, updated_at "
            "FROM scans WHERE %s ORDER BY updated_at DESC LIMIT 1"
            % " AND ".join(where)
        )
        with self._lock:
            row = self._connection.execute(query, params).fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "workspace": _loads(row["workspace_json"], {}),
            "report": _loads(row["report_json"], None),
            "status": row["status"],
            "updated_at": row["updated_at"],
        }

    def diff_workspace(self, workspace: ResearchWorkspace) -> Dict[str, Any]:
        previous = self.latest_scan(
            workspace.domain,
            exclude_scan_id=workspace.scan_id,
            complete_only=True,
        )
        diff = workspace.diff(previous.get("workspace") if previous else None)
        diff["baseline_scan_id"] = previous.get("scan_id") if previous else None
        diff["current_scan_id"] = workspace.scan_id
        diff["interpretation"] = (
            "removed means not observed in the current scan; it is not automatic proof of remediation"
        )
        return diff

    def list_scans(self, domain: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        if domain:
            query = (
                "SELECT scan_id, domain, target_url, status, is_checkpoint, created_at, updated_at "
                "FROM scans WHERE domain = ? ORDER BY updated_at DESC LIMIT ?"
            )
            params = ((domain or "").lower().rstrip("."), limit)
        else:
            query = (
                "SELECT scan_id, domain, target_url, status, is_checkpoint, created_at, updated_at "
                "FROM scans ORDER BY updated_at DESC LIMIT ?"
            )
            params = (limit,)
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None
