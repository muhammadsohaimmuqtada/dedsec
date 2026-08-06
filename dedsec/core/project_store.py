import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dedsec.core.evidence import redact_value
from dedsec.core.workspace import ResearchWorkspace


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ProjectStore:
    """SQLite-backed project history for resume, diff, and cross-scan asset knowledge.

    Persistent snapshots are redacted before storage. Authentication material is
    never intentionally stored in project history.
    """

    SCHEMA_VERSION = 1

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        self._connection = sqlite3.connect(self.path, timeout=30.0)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    workspace_json TEXT NOT NULL,
                    report_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scans_domain_created
                    ON scans(domain, created_at DESC);

                CREATE TABLE IF NOT EXISTS assets (
                    scan_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, asset_id),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_assets_kind_key ON assets(kind, key);

                CREATE TABLE IF NOT EXISTS edges (
                    scan_id TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, edge_id),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS requests (
                    scan_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, request_id),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_requests_method_url ON requests(method, url);

                CREATE TABLE IF NOT EXISTS observations (
                    scan_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, observation_id),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
                """
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO project_meta(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "ProjectStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def save_workspace(
        self,
        workspace: ResearchWorkspace,
        status: str = "complete",
        report: Optional[Dict[str, Any]] = None,
    ) -> None:
        raw_snapshot = workspace.snapshot()
        snapshot = redact_value(raw_snapshot)
        if not isinstance(snapshot, dict):
            raise ValueError("Workspace redaction produced invalid snapshot")
        created_at = str(workspace.metadata.get("generated_at") or _utc_now())
        workspace_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
        redacted_report = redact_value(report) if report is not None else None
        report_json = None
        if isinstance(redacted_report, dict):
            report_json = json.dumps(
                redacted_report,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        with self._connection:
            self._connection.execute(
                """
                INSERT OR REPLACE INTO scans(
                    scan_id, target_url, domain, created_at, status, workspace_json, report_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace.scan_id,
                    workspace.target_url,
                    workspace.domain,
                    created_at,
                    status,
                    workspace_json,
                    report_json,
                ),
            )
            self._connection.execute("DELETE FROM assets WHERE scan_id=?", (workspace.scan_id,))
            self._connection.execute("DELETE FROM edges WHERE scan_id=?", (workspace.scan_id,))
            self._connection.execute("DELETE FROM requests WHERE scan_id=?", (workspace.scan_id,))
            self._connection.execute("DELETE FROM observations WHERE scan_id=?", (workspace.scan_id,))

            self._connection.executemany(
                "INSERT INTO assets(scan_id, asset_id, kind, key, payload_json) VALUES(?, ?, ?, ?, ?)",
                [
                    (
                        workspace.scan_id,
                        item["id"],
                        item["kind"],
                        item["key"],
                        json.dumps(item, sort_keys=True, default=str),
                    )
                    for item in snapshot.get("assets", [])
                ],
            )
            self._connection.executemany(
                """
                INSERT INTO edges(
                    scan_id, edge_id, source_id, target_id, relation, payload_json
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        workspace.scan_id,
                        item["id"],
                        item["source_id"],
                        item["target_id"],
                        item["relation"],
                        json.dumps(item, sort_keys=True, default=str),
                    )
                    for item in snapshot.get("edges", [])
                ],
            )
            self._connection.executemany(
                "INSERT INTO requests(scan_id, request_id, method, url, payload_json) VALUES(?, ?, ?, ?, ?)",
                [
                    (
                        workspace.scan_id,
                        item["id"],
                        item["method"],
                        item["url"],
                        json.dumps(item, sort_keys=True, default=str),
                    )
                    for item in snapshot.get("requests", [])
                ],
            )
            self._connection.executemany(
                """
                INSERT INTO observations(
                    scan_id, observation_id, category, payload_json
                ) VALUES(?, ?, ?, ?)
                """,
                [
                    (
                        workspace.scan_id,
                        item["id"],
                        item["category"],
                        json.dumps(item, sort_keys=True, default=str),
                    )
                    for item in snapshot.get("observations", [])
                ],
            )

    def checkpoint(self, workspace: ResearchWorkspace) -> None:
        self.save_workspace(workspace, status="checkpoint")

    def load_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        row = self._connection.execute(
            "SELECT workspace_json FROM scans WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["workspace_json"])

    def latest_workspace(
        self,
        domain: str,
        exclude_scan_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if exclude_scan_id:
            row = self._connection.execute(
                """
                SELECT workspace_json FROM scans
                WHERE domain=? AND scan_id<>?
                ORDER BY created_at DESC LIMIT 1
                """,
                (domain.lower().rstrip("."), exclude_scan_id),
            ).fetchone()
        else:
            row = self._connection.execute(
                """
                SELECT workspace_json FROM scans
                WHERE domain=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (domain.lower().rstrip("."),),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["workspace_json"])

    def latest_checkpoint(self, domain: str) -> Optional[Dict[str, Any]]:
        row = self._connection.execute(
            """
            SELECT workspace_json FROM scans
            WHERE domain=? AND status='checkpoint'
            ORDER BY created_at DESC LIMIT 1
            """,
            (domain.lower().rstrip("."),),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["workspace_json"])

    def list_scans(self, domain: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        if domain:
            rows = self._connection.execute(
                """
                SELECT scan_id, target_url, domain, created_at, status
                FROM scans WHERE domain=? ORDER BY created_at DESC LIMIT ?
                """,
                (domain.lower().rstrip("."), max(1, int(limit))),
            ).fetchall()
        else:
            rows = self._connection.execute(
                """
                SELECT scan_id, target_url, domain, created_at, status
                FROM scans ORDER BY created_at DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def diff_workspace(self, workspace: ResearchWorkspace) -> Dict[str, Any]:
        previous = self.latest_workspace(workspace.domain, exclude_scan_id=workspace.scan_id)
        return workspace.diff(previous)
