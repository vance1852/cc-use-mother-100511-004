"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_candidates (
    candidate_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    version TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(model_name, version)
);
CREATE TABLE IF NOT EXISTS assessment_batches (
    batch_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    check_type TEXT NOT NULL CHECK(check_type IN ('vulnerability', 'permission', 'data_leak')),
    status TEXT NOT NULL CHECK(status IN ('open', 'completed')),
    submitted_by TEXT NOT NULL REFERENCES actors(actor_id),
    submitted_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES assessment_batches(batch_id),
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('open', 'resolved', 'reopened')),
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    reopen_count INTEGER NOT NULL DEFAULT 0 CHECK(reopen_count >= 0)
);
CREATE TABLE IF NOT EXISTS fix_evidences (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    summary TEXT NOT NULL,
    artifact_uri TEXT NOT NULL,
    submitted_by TEXT NOT NULL REFERENCES actors(actor_id),
    submitted_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exception_approvals (
    exception_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    reason TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    approved_by TEXT NOT NULL REFERENCES actors(actor_id),
    approved_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT
);
CREATE TABLE IF NOT EXISTS release_decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL UNIQUE,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    outcome TEXT NOT NULL CHECK(outcome IN ('approved', 'blocked')),
    reasons_json TEXT NOT NULL,
    exception_ids_json TEXT NOT NULL,
    request_id TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES actors(actor_id),
    decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_decision_invalidations (
    decision_id TEXT PRIMARY KEY REFERENCES release_decisions(decision_id),
    reason_code TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    invalidated_by TEXT NOT NULL,
    invalidated_at TEXT NOT NULL
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)
        # 所有线程共享一个连接，事务必须在 Python 层面互斥，
        # 否则并发线程的 BEGIN 会被同一连接拒绝为嵌套事务。
        self._transaction_lock = threading.RLock()

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交；并发事务按到达顺序串行执行。"""

        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
