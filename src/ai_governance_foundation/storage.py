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
    model_id TEXT NOT NULL,
    version TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(model_id, version)
);
CREATE TABLE IF NOT EXISTS evaluation_batches (
    batch_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    check_family TEXT NOT NULL,
    completed INTEGER NOT NULL CHECK(completed IN (0, 1)),
    version_pin TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES evaluation_batches(batch_id),
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    check_family TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    blocking INTEGER NOT NULL CHECK(blocking IN (0, 1)),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remediation_evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    kind TEXT NOT NULL,
    reference TEXT NOT NULL,
    version_pin TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exception_approvals (
    exception_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    approver TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'expired')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS release_decisions (
    decision_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(candidate_id),
    result TEXT NOT NULL CHECK(result IN ('approved', 'rejected')),
    basis_candidate_version TEXT NOT NULL,
    basis_digest TEXT NOT NULL,
    rationale TEXT NOT NULL,
    blocking_reasons_json TEXT NOT NULL,
    check_summary_json TEXT NOT NULL,
    supersedes_decision_id TEXT REFERENCES release_decisions(decision_id) DEFERRABLE INITIALLY DEFERRED,
    superseded_by_decision_id TEXT REFERENCES release_decisions(decision_id) DEFERRABLE INITIALLY DEFERRED,
    invalidated_by TEXT,
    invalidated_reason TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    invalidated_at TEXT
);
-- 同一候选版本任意时刻至多有一条生效决定；被废止/被取代的行置 NULL。
CREATE UNIQUE INDEX IF NOT EXISTS idx_release_decisions_live
    ON release_decisions(candidate_id)
    WHERE superseded_by_decision_id IS NULL AND invalidated_at IS NULL;
-- 决定生效期间其依据所引用的证据/例外不得被删除或改写。
CREATE TABLE IF NOT EXISTS decision_basis_items (
    decision_id TEXT NOT NULL REFERENCES release_decisions(decision_id),
    item_type TEXT NOT NULL,
    item_id TEXT NOT NULL,
    PRIMARY KEY(decision_id, item_type, item_id)
);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        # 多线程共享同一 SQLite 连接时，用进程内锁串行化写事务，
        # 配合 BEGIN IMMEDIATE 保证并发请求不会交错提交。
        self._write_lock = threading.RLock()
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        with self._write_lock:
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
