"""实现模型发布门禁：评估批次、发现项、修复证据、例外批准与发布决定。

一致性约定：
- 所有写路径都在 ``BEGIN IMMEDIATE`` 事务内完成校验、写入、失效登记和审计追加，
  因此并发请求被 SQLite 写锁串行化，不会出现两个互相矛盾的决定。
- 每个写接口都通过 ``request_id`` 幂等：服务重启后客户端用同一编号重试，
  只会回放首次提交的结果，不会重复产生决定。
- 发布决定只追加不修改；关键发现被重新打开、例外被撤销或例外过期时，
  向 ``release_decision_invalidations`` 追加失效记录，历史决定保持原样。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock
from .errors import ConflictError, NotFoundError, ValidationError
from .service import DomainService
from .storage import Database

REQUIRED_CHECK_TYPES = ("vulnerability", "permission", "data_leak")
SEVERITIES = ("critical", "high", "medium", "low")
CHECK_TYPE_LABELS = {
    "vulnerability": "漏洞评估",
    "permission": "权限评估",
    "data_leak": "数据泄露评估",
}


def parse_timestamp(value: str, field: str) -> datetime:
    """解析带时区的 ISO 8601 时间并归一到 UTC。"""

    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} 必须是 ISO 8601 时间") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} 必须包含时区")
    return parsed.astimezone(timezone.utc)


class ReleaseGateService(DomainService):
    """在基础服务之上提供模型发布门禁能力。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        super().__init__(database, clock)

    # ---------- 通用助手 ----------

    def _idempotent_response(self, connection, *, request_id: str, action: str,
                             payload: dict[str, Any],
                             create: Callable[[], tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
        """与基础服务相同的幂等规则，但向调用方返回完整响应体。"""

        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            response = json.loads(row["response_json"])
            response["replayed"] = True
            return response
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,response_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        response["replayed"] = False
        return response

    def _candidate(self, connection, candidate_id: str):
        row = connection.execute(
            "SELECT * FROM release_candidates WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("发布候选版本不存在")
        return row

    def _batch(self, connection, batch_id: str):
        row = connection.execute(
            "SELECT * FROM assessment_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("评估批次不存在")
        return row

    def _finding(self, connection, finding_id: str):
        row = connection.execute(
            "SELECT f.*, b.candidate_id AS candidate_id, b.check_type AS check_type "
            "FROM findings f JOIN assessment_batches b ON b.batch_id=f.batch_id "
            "WHERE f.finding_id=?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("发现项不存在")
        return row

    def _exception(self, connection, exception_id: str):
        row = connection.execute(
            "SELECT * FROM exception_approvals WHERE exception_id=?", (exception_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("例外批准不存在")
        return row

    # ---------- 门禁评估 ----------

    def _governing_batches(self, connection, candidate_id: str) -> dict[str, Any]:
        """每类必需检查取最近提交的已完成批次作为管辖评估。"""

        rows = connection.execute(
            "SELECT * FROM assessment_batches WHERE candidate_id=? AND status='completed' "
            "ORDER BY rowid DESC",
            (candidate_id,),
        ).fetchall()
        governing: dict[str, Any] = {}
        for row in rows:
            governing.setdefault(row["check_type"], row)
        return governing

    def _valid_exception(self, connection, finding_id: str, now: datetime):
        rows = connection.execute(
            "SELECT * FROM exception_approvals WHERE finding_id=? AND revoked_at IS NULL "
            "ORDER BY rowid DESC",
            (finding_id,),
        ).fetchall()
        for row in rows:
            if parse_timestamp(row["valid_until"], "valid_until") > now:
                return row
        return None

    def _finding_blocker(self, connection, finding) -> dict[str, Any]:
        latest_exception = connection.execute(
            "SELECT * FROM exception_approvals WHERE finding_id=? ORDER BY rowid DESC LIMIT 1",
            (finding["finding_id"],),
        ).fetchone()
        base = {
            "finding_id": finding["finding_id"],
            "severity": finding["severity"],
            "status": finding["status"],
            "title": finding["title"],
        }
        if latest_exception is not None and latest_exception["revoked_at"] is not None:
            return {**base, "code": "exception_revoked",
                    "exception_id": latest_exception["exception_id"],
                    "message": "覆盖该发现项的例外批准已被撤销",
                    "recovery": "重新获得仍在有效期内的例外批准，或提交修复证据关闭发现项"}
        if latest_exception is not None:
            return {**base, "code": "exception_expired",
                    "exception_id": latest_exception["exception_id"],
                    "valid_until": latest_exception["valid_until"],
                    "message": "覆盖该发现项的例外批准已经过期",
                    "recovery": "续期或重新批准例外，或提交修复证据关闭发现项"}
        return {**base, "code": "finding_unresolved",
                "message": "发现项未关闭且没有仍在有效期内的例外批准",
                "recovery": "提交修复证据关闭发现项，或获得仍在有效期内的例外批准"}

    def _evaluate(self, connection, candidate_id: str, now: datetime) -> dict[str, Any]:
        """计算候选版本当前是否满足发布条件，并给出逐项阻断依据。"""

        governing = self._governing_batches(connection, candidate_id)
        blockers: list[dict[str, Any]] = []
        for check_type in REQUIRED_CHECK_TYPES:
            if check_type not in governing:
                blockers.append({
                    "code": "missing_completed_check",
                    "check_type": check_type,
                    "message": f"{CHECK_TYPE_LABELS[check_type]}在该候选版本上没有已完成的评估批次",
                    "recovery": "由安全评估组在该候选版本上提交并完成对应评估批次后重新生成决定",
                })
        relied: list[str] = []
        for batch in governing.values():
            findings = connection.execute(
                "SELECT * FROM findings WHERE batch_id=? ORDER BY rowid", (batch["batch_id"],)
            ).fetchall()
            for finding in findings:
                if finding["status"] == "resolved":
                    continue
                exception = self._valid_exception(connection, finding["finding_id"], now)
                if exception is not None:
                    relied.append(exception["exception_id"])
                else:
                    blockers.append(self._finding_blocker(connection, finding))
        return {
            "outcome": "blocked" if blockers else "approved",
            "blockers": blockers,
            "relied_exception_ids": sorted(set(relied)),
            "governing_batches": {check_type: batch["batch_id"]
                                  for check_type, batch in governing.items()},
        }

    # ---------- 决定失效 ----------

    def _invalidate(self, connection, decision_id: str, *, reason_code: str,
                    detail: dict[str, Any], invalidated_by: str) -> bool:
        """追加一条失效记录；同一决定只失效一次，历史决定行保持不变。"""

        existing = connection.execute(
            "SELECT 1 FROM release_decision_invalidations WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if existing:
            return False
        connection.execute(
            "INSERT INTO release_decision_invalidations(decision_id,reason_code,detail_json,invalidated_by,invalidated_at) "
            "VALUES(?,?,?,?,?)",
            (decision_id, reason_code, canonical_json(detail), invalidated_by, self._now()),
        )
        append_event(connection, actor_id=invalidated_by, action="release_decision.invalidated",
                     resource_type="release_decision", resource_id=decision_id,
                     detail={"reason_code": reason_code, **detail}, occurred_at=self._now())
        return True

    def _valid_approvals(self, connection, candidate_id: str) -> list[Any]:
        return connection.execute(
            "SELECT * FROM release_decisions WHERE candidate_id=? AND outcome='approved' "
            "AND decision_id NOT IN (SELECT decision_id FROM release_decision_invalidations) "
            "ORDER BY sequence",
            (candidate_id,),
        ).fetchall()

    def _invalidate_valid_approvals(self, connection, candidate_id: str, *, reason_code: str,
                                    detail: dict[str, Any], invalidated_by: str,
                                    required_exception_id: str | None = None) -> list[str]:
        """让候选版本下仍然有效的批准决定失效，返回被失效的决定编号。"""

        invalidated: list[str] = []
        for row in self._valid_approvals(connection, candidate_id):
            if required_exception_id is not None:
                relied = json.loads(row["exception_ids_json"])
                if required_exception_id not in relied:
                    continue
            if self._invalidate(connection, row["decision_id"], reason_code=reason_code,
                                detail=detail, invalidated_by=invalidated_by):
                invalidated.append(row["decision_id"])
        return invalidated

    def _sweep_expired_exceptions(self, connection, candidate_id: str, now: datetime) -> None:
        """把依赖已过期例外的有效批准登记为失效（惰性扫描，单向不回溯）。"""

        for row in self._valid_approvals(connection, candidate_id):
            relied = json.loads(row["exception_ids_json"])
            if not relied:
                continue
            placeholders = ",".join("?" for _ in relied)
            exceptions = connection.execute(
                f"SELECT * FROM exception_approvals WHERE exception_id IN ({placeholders})",
                relied,
            ).fetchall()
            expired = [item["exception_id"] for item in exceptions
                       if parse_timestamp(item["valid_until"], "valid_until") <= now]
            if expired:
                self._invalidate(connection, row["decision_id"],
                                 reason_code="exception_expired",
                                 detail={"exception_ids": sorted(expired)},
                                 invalidated_by="system")

    # ---------- 写接口 ----------

    def register_candidate(self, *, request_id: str, actor_id: str, candidate_id: str,
                           model_name: str, version: str, note: str = "") -> dict[str, Any]:
        payload = {"actor_id": actor_id, "candidate_id": candidate_id,
                   "model_name": model_name, "version": version, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            candidate_id = self._identifier(candidate_id, "candidate_id")
            model_name = self._identifier(model_name, "model_name")
            version = self._identifier(version, "version")
            note = self._text(note, "note", 500) if note else ""

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO release_candidates(candidate_id,model_name,version,note,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?)",
                        (candidate_id, model_name, version, note, actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("候选版本编号或模型版本组合已经存在") from exc
                append_event(connection, actor_id=actor_id, action="release_candidate.registered",
                             resource_type="release_candidate", resource_id=candidate_id,
                             detail={"model_name": model_name, "version": version},
                             occurred_at=self._now())
                return "release_candidate", candidate_id, {"candidate_id": candidate_id,
                                                           "model_name": model_name,
                                                           "version": version}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="register_candidate", payload=payload,
                                             create=create)

    def submit_batch(self, *, request_id: str, actor_id: str, candidate_id: str,
                     check_type: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "candidate_id": candidate_id, "check_type": check_type}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            self._candidate(connection, candidate_id)
            if check_type not in REQUIRED_CHECK_TYPES:
                raise ValidationError("check_type 必须是 vulnerability、permission 或 data_leak")

            def create() -> tuple[str, str, dict[str, Any]]:
                batch_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO assessment_batches(batch_id,candidate_id,check_type,status,submitted_by,submitted_at) "
                    "VALUES(?,?,?,'open',?,?)",
                    (batch_id, candidate_id, check_type, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="assessment_batch.submitted",
                             resource_type="assessment_batch", resource_id=batch_id,
                             detail={"candidate_id": candidate_id, "check_type": check_type},
                             occurred_at=self._now())
                return "assessment_batch", batch_id, {"batch_id": batch_id,
                                                      "candidate_id": candidate_id,
                                                      "check_type": check_type,
                                                      "status": "open"}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="submit_batch", payload=payload, create=create)

    def add_finding(self, *, request_id: str, actor_id: str, batch_id: str, severity: str,
                    title: str, description: str = "") -> dict[str, Any]:
        payload = {"actor_id": actor_id, "batch_id": batch_id, "severity": severity,
                   "title": title, "description": description}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            batch = self._batch(connection, batch_id)
            if batch["status"] != "open":
                raise ConflictError("评估批次已完成，不能追加发现项")
            if severity not in SEVERITIES:
                raise ValidationError("severity 必须是 critical、high、medium 或 low")
            title = self._text(title, "title")
            description = self._text(description, "description", 1000) if description else ""

            def create() -> tuple[str, str, dict[str, Any]]:
                finding_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO findings(finding_id,batch_id,severity,title,description,status,created_by,created_at) "
                    "VALUES(?,?,?,?,?,'open',?,?)",
                    (finding_id, batch_id, severity, title, description, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="finding.reported",
                             resource_type="finding", resource_id=finding_id,
                             detail={"batch_id": batch_id, "severity": severity, "title": title},
                             occurred_at=self._now())
                return "finding", finding_id, {"finding_id": finding_id, "batch_id": batch_id,
                                               "severity": severity, "status": "open"}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="add_finding", payload=payload, create=create)

    def complete_batch(self, *, request_id: str, actor_id: str, batch_id: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "batch_id": batch_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            batch = self._batch(connection, batch_id)
            if batch["status"] != "open":
                raise ConflictError("评估批次已经完成")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE assessment_batches SET status='completed', completed_at=? WHERE batch_id=?",
                    (self._now(), batch_id),
                )
                append_event(connection, actor_id=actor_id, action="assessment_batch.completed",
                             resource_type="assessment_batch", resource_id=batch_id,
                             detail={"candidate_id": batch["candidate_id"],
                                     "check_type": batch["check_type"]},
                             occurred_at=self._now())
                return "assessment_batch", batch_id, {"batch_id": batch_id, "status": "completed"}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="complete_batch", payload=payload, create=create)

    def resolve_finding(self, *, request_id: str, actor_id: str, finding_id: str,
                        summary: str, artifact_uri: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "finding_id": finding_id,
                   "summary": summary, "artifact_uri": artifact_uri}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            finding = self._finding(connection, finding_id)
            if finding["status"] == "resolved":
                raise ConflictError("发现项已经关闭")
            summary = self._text(summary, "summary", 500)
            artifact_uri = self._text(artifact_uri, "artifact_uri", 500)

            def create() -> tuple[str, str, dict[str, Any]]:
                evidence_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO fix_evidences(evidence_id,finding_id,summary,artifact_uri,submitted_by,submitted_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (evidence_id, finding_id, summary, artifact_uri, actor_id, self._now()),
                )
                connection.execute(
                    "UPDATE findings SET status='resolved', resolved_at=? WHERE finding_id=?",
                    (self._now(), finding_id),
                )
                append_event(connection, actor_id=actor_id, action="finding.resolved",
                             resource_type="finding", resource_id=finding_id,
                             detail={"evidence_id": evidence_id, "summary": summary,
                                     "artifact_uri": artifact_uri},
                             occurred_at=self._now())
                return "finding", finding_id, {"finding_id": finding_id, "status": "resolved",
                                               "evidence_id": evidence_id}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="resolve_finding", payload=payload, create=create)

    def reopen_finding(self, *, request_id: str, actor_id: str, finding_id: str,
                       reason: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "finding_id": finding_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            finding = self._finding(connection, finding_id)
            if finding["status"] != "resolved":
                raise ConflictError("只有已关闭的发现项才能重新打开")
            reason = self._text(reason, "reason", 500)

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE findings SET status='reopened', reopen_count=reopen_count+1 WHERE finding_id=?",
                    (finding_id,),
                )
                append_event(connection, actor_id=actor_id, action="finding.reopened",
                             resource_type="finding", resource_id=finding_id,
                             detail={"reason": reason, "severity": finding["severity"]},
                             occurred_at=self._now())
                invalidated: list[str] = []
                if finding["severity"] == "critical":
                    invalidated = self._invalidate_valid_approvals(
                        connection, finding["candidate_id"],
                        reason_code="critical_finding_reopened",
                        detail={"finding_id": finding_id, "title": finding["title"]},
                        invalidated_by=actor_id)
                return "finding", finding_id, {"finding_id": finding_id, "status": "reopened",
                                               "invalidated_decision_ids": invalidated}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="reopen_finding", payload=payload, create=create)

    def approve_exception(self, *, request_id: str, actor_id: str, finding_id: str,
                          reason: str, valid_until: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "finding_id": finding_id,
                   "reason": reason, "valid_until": valid_until}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            self._finding(connection, finding_id)
            reason = self._text(reason, "reason", 500)
            valid_until_dt = parse_timestamp(valid_until, "valid_until")
            if valid_until_dt <= self.clock.now():
                raise ValidationError("valid_until 必须晚于当前时间")
            valid_until_text = valid_until_dt.isoformat().replace("+00:00", "Z")

            def create() -> tuple[str, str, dict[str, Any]]:
                exception_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO exception_approvals(exception_id,finding_id,reason,valid_until,approved_by,approved_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (exception_id, finding_id, reason, valid_until_text, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="exception.approved",
                             resource_type="exception_approval", resource_id=exception_id,
                             detail={"finding_id": finding_id, "valid_until": valid_until_text},
                             occurred_at=self._now())
                return "exception_approval", exception_id, {"exception_id": exception_id,
                                                            "finding_id": finding_id,
                                                            "valid_until": valid_until_text}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="approve_exception", payload=payload, create=create)

    def revoke_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                         reason: str) -> dict[str, Any]:
        payload = {"actor_id": actor_id, "exception_id": exception_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            exception = self._exception(connection, exception_id)
            if exception["revoked_at"] is not None:
                raise ConflictError("例外批准已经撤销")
            reason = self._text(reason, "reason", 500)
            finding = self._finding(connection, exception["finding_id"])

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE exception_approvals SET revoked_at=?, revoked_by=?, revoke_reason=? "
                    "WHERE exception_id=?",
                    (self._now(), actor_id, reason, exception_id),
                )
                append_event(connection, actor_id=actor_id, action="exception.revoked",
                             resource_type="exception_approval", resource_id=exception_id,
                             detail={"finding_id": exception["finding_id"], "reason": reason},
                             occurred_at=self._now())
                invalidated = self._invalidate_valid_approvals(
                    connection, finding["candidate_id"],
                    reason_code="exception_revoked",
                    detail={"exception_id": exception_id,
                            "finding_id": exception["finding_id"]},
                    invalidated_by=actor_id,
                    required_exception_id=exception_id)
                return "exception_approval", exception_id, {
                    "exception_id": exception_id, "revoked": True,
                    "invalidated_decision_ids": invalidated}

            return self._idempotent_response(connection, request_id=request_id,
                                             action="revoke_exception", payload=payload, create=create)

    def generate_decision(self, *, request_id: str, actor_id: str,
                          candidate_id: str) -> dict[str, Any]:
        """在同一事务内完成评估与决定落库，保证并发下决定与依据一致。"""

        payload = {"actor_id": actor_id, "candidate_id": candidate_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            self._candidate(connection, candidate_id)
            now = self.clock.now()
            self._sweep_expired_exceptions(connection, candidate_id, now)

            def create() -> tuple[str, str, dict[str, Any]]:
                evaluation = self._evaluate(connection, candidate_id, now)
                decision_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO release_decisions(decision_id,candidate_id,outcome,reasons_json,"
                    "exception_ids_json,request_id,decided_by,decided_at) VALUES(?,?,?,?,?,?,?,?)",
                    (decision_id, candidate_id, evaluation["outcome"],
                     canonical_json(evaluation["blockers"]),
                     canonical_json(evaluation["relied_exception_ids"]),
                     request_id, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="release_decision.generated",
                             resource_type="release_decision", resource_id=decision_id,
                             detail={"candidate_id": candidate_id,
                                     "outcome": evaluation["outcome"],
                                     "blocker_count": len(evaluation["blockers"])},
                             occurred_at=self._now())
                return "release_decision", decision_id, {
                    "decision_id": decision_id,
                    "candidate_id": candidate_id,
                    "outcome": evaluation["outcome"],
                    "blockers": evaluation["blockers"],
                    "relied_exception_ids": evaluation["relied_exception_ids"],
                    "decided_by": actor_id,
                    "decided_at": self._now(),
                }

            return self._idempotent_response(connection, request_id=request_id,
                                             action="generate_decision", payload=payload,
                                             create=create)

    # ---------- 查询接口 ----------

    def gate_status(self, candidate_id: str) -> dict[str, Any]:
        """实时评估候选版本是否可发布，并给出阻断依据与恢复条件。"""

        with self.database.transaction(immediate=True) as connection:
            self._candidate(connection, candidate_id)
            now = self.clock.now()
            self._sweep_expired_exceptions(connection, candidate_id, now)
            evaluation = self._evaluate(connection, candidate_id, now)
            return {"candidate_id": candidate_id, "outcome": evaluation["outcome"],
                    "blockers": evaluation["blockers"],
                    "governing_batches": evaluation["governing_batches"],
                    "evaluated_at": self._now()}

    def current_decision(self, candidate_id: str) -> dict[str, Any]:
        """返回最近一次决定、其当前有效性，以及当前仍需满足的恢复条件。"""

        with self.database.transaction(immediate=True) as connection:
            self._candidate(connection, candidate_id)
            now = self.clock.now()
            self._sweep_expired_exceptions(connection, candidate_id, now)
            row = connection.execute(
                "SELECT * FROM release_decisions WHERE candidate_id=? ORDER BY sequence DESC LIMIT 1",
                (candidate_id,),
            ).fetchone()
            evaluation = self._evaluate(connection, candidate_id, now)
            if row is None:
                return {"candidate_id": candidate_id, "decision": None, "valid": False,
                        "message": "尚未生成发布决定",
                        "current_blockers": evaluation["blockers"]}
            invalidation = connection.execute(
                "SELECT * FROM release_decision_invalidations WHERE decision_id=?",
                (row["decision_id"],),
            ).fetchone()
            valid = row["outcome"] == "approved" and invalidation is None
            decision = {"decision_id": row["decision_id"], "outcome": row["outcome"],
                        "blockers": json.loads(row["reasons_json"]),
                        "relied_exception_ids": json.loads(row["exception_ids_json"]),
                        "decided_by": row["decided_by"], "decided_at": row["decided_at"]}
            result: dict[str, Any] = {"candidate_id": candidate_id, "decision": decision,
                                      "valid": valid,
                                      "current_blockers": evaluation["blockers"]}
            if invalidation is not None:
                result["invalidation"] = {
                    "reason_code": invalidation["reason_code"],
                    "detail": json.loads(invalidation["detail_json"]),
                    "invalidated_by": invalidation["invalidated_by"],
                    "invalidated_at": invalidation["invalidated_at"],
                }
            return result

    def list_decisions(self, candidate_id: str) -> list[dict[str, Any]]:
        """按生成顺序返回全部决定及其失效记录，历史不被覆盖。"""

        with self.database.transaction(immediate=True) as connection:
            self._candidate(connection, candidate_id)
            self._sweep_expired_exceptions(connection, candidate_id, self.clock.now())
            rows = connection.execute(
                "SELECT d.*, i.reason_code AS inv_reason, i.detail_json AS inv_detail, "
                "i.invalidated_by AS inv_by, i.invalidated_at AS inv_at "
                "FROM release_decisions d "
                "LEFT JOIN release_decision_invalidations i ON i.decision_id=d.decision_id "
                "WHERE d.candidate_id=? ORDER BY d.sequence",
                (candidate_id,),
            ).fetchall()
            decisions = []
            for row in rows:
                item = {"sequence": row["sequence"], "decision_id": row["decision_id"],
                        "outcome": row["outcome"], "blockers": json.loads(row["reasons_json"]),
                        "relied_exception_ids": json.loads(row["exception_ids_json"]),
                        "decided_by": row["decided_by"], "decided_at": row["decided_at"],
                        "invalidated": row["inv_reason"] is not None}
                if row["inv_reason"] is not None:
                    item["invalidation"] = {"reason_code": row["inv_reason"],
                                            "detail": json.loads(row["inv_detail"]),
                                            "invalidated_by": row["inv_by"],
                                            "invalidated_at": row["inv_at"]}
                decisions.append(item)
            return decisions

    def list_candidates(self, model_name: str | None = None) -> list[dict[str, Any]]:
        parameters: list[Any] = []
        query = "SELECT * FROM release_candidates"
        if model_name:
            query += " WHERE model_name=?"
            parameters.append(model_name)
        query += " ORDER BY created_at, candidate_id"
        return [{"candidate_id": row["candidate_id"], "model_name": row["model_name"],
                 "version": row["version"], "note": row["note"],
                 "created_by": row["created_by"], "created_at": row["created_at"]}
                for row in self.database.connection.execute(query, parameters)]

    def list_batches(self, candidate_id: str) -> list[dict[str, Any]]:
        rows = self.database.connection.execute(
            "SELECT * FROM assessment_batches WHERE candidate_id=? ORDER BY rowid",
            (candidate_id,),
        ).fetchall()
        return [{"batch_id": row["batch_id"], "candidate_id": row["candidate_id"],
                 "check_type": row["check_type"], "status": row["status"],
                 "submitted_by": row["submitted_by"], "submitted_at": row["submitted_at"],
                 "completed_at": row["completed_at"]} for row in rows]

    def list_findings(self, candidate_id: str) -> list[dict[str, Any]]:
        rows = self.database.connection.execute(
            "SELECT f.*, b.check_type AS check_type FROM findings f "
            "JOIN assessment_batches b ON b.batch_id=f.batch_id "
            "WHERE b.candidate_id=? ORDER BY f.rowid",
            (candidate_id,),
        ).fetchall()
        findings = []
        for row in rows:
            exceptions = self.database.connection.execute(
                "SELECT * FROM exception_approvals WHERE finding_id=? ORDER BY rowid",
                (row["finding_id"],),
            ).fetchall()
            findings.append({
                "finding_id": row["finding_id"], "batch_id": row["batch_id"],
                "check_type": row["check_type"], "severity": row["severity"],
                "title": row["title"], "description": row["description"],
                "status": row["status"], "reopen_count": row["reopen_count"],
                "created_by": row["created_by"], "created_at": row["created_at"],
                "resolved_at": row["resolved_at"],
                "exceptions": [{"exception_id": item["exception_id"],
                                "valid_until": item["valid_until"],
                                "revoked": item["revoked_at"] is not None}
                               for item in exceptions],
            })
        return findings
