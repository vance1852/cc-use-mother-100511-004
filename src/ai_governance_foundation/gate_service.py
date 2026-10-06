"""模型发布门禁：把评估批次、发现项、修复证据、例外批准与发布候选版本关联起来。

门禁规则：
1. 每个必需检查族（漏洞、权限、数据泄露）的最新批次必须在候选版本自身上完成；
2. 每个阻断级发现项必须在同一版本上有修复证据，或持有仍有效的例外批准；
3. 发现项被重新打开、例外被撤销/到期，或出现新一轮未完成评估时，已生效的
   批准决定立即失效（保留历史行，不覆盖、不删除）；
4. 发布决定只在单个立即事务内依据状态快照生成，并发提交与进程重启都不会
   产生两条互相矛盾的生效决定。
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .gate_models import (
    DECISION_APPROVED,
    DECISION_INVALIDATED,
    DECISION_REJECTED,
    DECISION_SUPERSEDED,
    EVIDENCE_KINDS,
    REQUIRED_CHECK_FAMILIES,
    SEVERITIES,
    BlockingReason,
    ExceptionApproval,
    Finding,
    GateEvaluation,
    GateWriteReceipt,
    ReleaseCandidate,
    ReleaseDecision,
)
from .models import Actor
from .storage import Database


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
BLOCKING_SEVERITIES = frozenset({"critical", "high"})


class GateService:
    """协调门禁状态机、决定快照、失效规则、幂等与审计。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 500) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _parse_timestamp(self, value: str, field: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是 ISO-8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return parsed.astimezone(timezone.utc)

    def _timestamp_text(self, value: datetime) -> str:
        return value.isoformat().replace("+00:00", "Z")

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"],
                      row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _require(self, actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _candidate(self, connection, candidate_id: str):
        row = connection.execute(
            "SELECT * FROM release_candidates WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("发布候选版本不存在")
        return row

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any],
                    create: Callable[[], tuple[str, str, dict[str, Any]]]) -> GateWriteReceipt:
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return GateWriteReceipt(request_id, row["resource_type"], row["resource_id"], True)
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,"
            "resource_id,response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return GateWriteReceipt(request_id, resource_type, resource_id, False)

    # ------------------------------------------------------------------ 登记

    def register_candidate(self, *, request_id: str, actor_id: str, candidate_id: str,
                           model_id: str, version: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "candidate_id": candidate_id,
                   "model_id": model_id, "version": version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            candidate_id = self._identifier(candidate_id, "candidate_id")
            model_id = self._identifier(model_id, "model_id")
            version = self._text(version, "version", 120)

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO release_candidates(candidate_id,model_id,version,created_by,created_at) "
                        "VALUES(?,?,?,?,?)",
                        (candidate_id, model_id, version, actor_id, self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("候选版本编号或 模型+版本 已经存在") from exc
                append_event(connection, actor_id=actor_id, action="release_candidate.registered",
                             resource_type="release_candidate", resource_id=candidate_id,
                             detail={"model_id": model_id, "version": version},
                             occurred_at=self._now())
                return "release_candidate", candidate_id, {"candidate_id": candidate_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.register_candidate", payload=payload,
                                    create=create)

    def register_batch(self, *, request_id: str, actor_id: str, batch_id: str,
                       candidate_id: str, check_family: str, version_pin: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "batch_id": batch_id, "candidate_id": candidate_id,
                   "check_family": check_family, "version_pin": version_pin}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            candidate = self._candidate(connection, candidate_id)
            batch_id = self._identifier(batch_id, "batch_id")
            if check_family not in REQUIRED_CHECK_FAMILIES:
                raise ValidationError("check_family 不属于必需检查族")
            version_pin = self._text(version_pin, "version_pin", 120)
            if version_pin != candidate["version"]:
                raise ValidationError(
                    f"批次必须固定在候选版本 {candidate['version']} 上，收到 {version_pin}"
                )

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO evaluation_batches(batch_id,candidate_id,check_family,completed,"
                        "version_pin,created_by,created_at,completed_at) VALUES(?,?,?,0,?,?,?,NULL)",
                        (batch_id, candidate_id, check_family, version_pin,
                         actor_id, self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("评估批次编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="evaluation_batch.registered",
                             resource_type="evaluation_batch", resource_id=batch_id,
                             detail={"candidate_id": candidate_id, "check_family": check_family,
                                     "version_pin": version_pin},
                             occurred_at=self._now())
                # 新一轮评估开始后，旧批准所依据的“已完成”状态不再成立。
                self._invalidate_live_approval(
                    connection, candidate=candidate,
                    reason_code="evaluation_superseded",
                    reason_message=f"检查族 {check_family} 开启了新的评估批次 {batch_id}",
                    refs={"batch_id": batch_id, "check_family": check_family},
                    actor_id=actor_id,
                )
                return "evaluation_batch", batch_id, {"batch_id": batch_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.register_batch", payload=payload,
                                    create=create)

    def complete_batch(self, *, request_id: str, actor_id: str, batch_id: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "batch_id": batch_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            batch = connection.execute(
                "SELECT * FROM evaluation_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if batch is None:
                raise NotFoundError("评估批次不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                if batch["completed"]:
                    raise ConflictError("评估批次已经完成，不能重复完成")
                connection.execute(
                    "UPDATE evaluation_batches SET completed=1, completed_at=? WHERE batch_id=?",
                    (self._now(), batch_id),
                )
                append_event(connection, actor_id=actor_id, action="evaluation_batch.completed",
                             resource_type="evaluation_batch", resource_id=batch_id,
                             detail={"candidate_id": batch["candidate_id"],
                                     "check_family": batch["check_family"],
                                     "version_pin": batch["version_pin"]},
                             occurred_at=self._now())
                return "evaluation_batch", batch_id, {"batch_id": batch_id, "completed": True}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.complete_batch", payload=payload,
                                    create=create)

    def record_finding(self, *, request_id: str, actor_id: str, finding_id: str,
                       batch_id: str, severity: str, title: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "finding_id": finding_id, "batch_id": batch_id,
                   "severity": severity, "title": title}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            batch = connection.execute(
                "SELECT * FROM evaluation_batches WHERE batch_id=?", (batch_id,)
            ).fetchone()
            if batch is None:
                raise NotFoundError("评估批次不存在")
            candidate = self._candidate(connection, batch["candidate_id"])
            finding_id = self._identifier(finding_id, "finding_id")
            if severity not in SEVERITIES:
                raise ValidationError("severity 不被支持")
            title = self._text(title, "title")
            blocking = severity in BLOCKING_SEVERITIES

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO findings(finding_id,batch_id,candidate_id,check_family,"
                        "severity,title,status,blocking,created_by,created_at,updated_at) "
                        "VALUES(?,?,?,?,?,?,'open',?,?,?,?)",
                        (finding_id, batch_id, candidate["candidate_id"], batch["check_family"],
                         severity, title, 1 if blocking else 0, actor_id,
                         self._now(), self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("发现项编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="finding.recorded",
                             resource_type="finding", resource_id=finding_id,
                             detail={"candidate_id": candidate["candidate_id"],
                                     "batch_id": batch_id, "severity": severity,
                                     "blocking": blocking, "title": title},
                             occurred_at=self._now())
                if blocking:
                    self._invalidate_live_approval(
                        connection, candidate=candidate,
                        reason_code="new_blocking_finding",
                        reason_message=f"出现新的阻断级发现项 {finding_id}（{severity}）",
                        refs={"finding_id": finding_id, "severity": severity},
                        actor_id=actor_id,
                    )
                return "finding", finding_id, {"finding_id": finding_id, "blocking": blocking}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.record_finding", payload=payload,
                                    create=create)

    def add_evidence(self, *, request_id: str, actor_id: str, evidence_id: str,
                     finding_id: str, kind: str, reference: str,
                     version_pin: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "evidence_id": evidence_id,
                   "finding_id": finding_id, "kind": kind, "reference": reference,
                   "version_pin": version_pin}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator", "reviewer")
            finding = connection.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if finding is None:
                raise NotFoundError("发现项不存在")
            candidate = self._candidate(connection, finding["candidate_id"])
            evidence_id = self._identifier(evidence_id, "evidence_id")
            if kind not in EVIDENCE_KINDS:
                raise ValidationError("证据类别不被支持")
            reference = self._text(reference, "reference")
            version_pin = self._text(version_pin, "version_pin", 120)
            # 证据可以固定在任意版本上；只有与候选版本一致的证据才能解除阻断，
            # 其他版本的证据会保留并在门禁说明中明确指出版本不符。
            same_version = version_pin == candidate["version"]

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO remediation_evidence(evidence_id,finding_id,candidate_id,kind,"
                        "reference,version_pin,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                        (evidence_id, finding_id, candidate["candidate_id"], kind, reference,
                         version_pin, actor_id, self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("证据编号已经存在") from exc
                now = self._now()
                # 新的同版本证据意味着问题在候选版本上被重新修复：重新打开的发现项
                # 也可据此回到已缓解状态（恢复条件）。其他版本的证据不改变状态。
                if same_version and finding["status"] in ("open", "reopened"):
                    connection.execute(
                        "UPDATE findings SET status='mitigated', updated_at=? WHERE finding_id=?",
                        (now, finding_id),
                    )
                append_event(connection, actor_id=actor_id, action="remediation_evidence.added",
                             resource_type="remediation_evidence", resource_id=evidence_id,
                             detail={"candidate_id": candidate["candidate_id"],
                                     "finding_id": finding_id, "kind": kind,
                                     "version_pin": version_pin,
                                     "same_version": same_version, "reference": reference},
                             occurred_at=now)
                return "remediation_evidence", evidence_id, {
                    "evidence_id": evidence_id, "same_version": same_version,
                }

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.add_evidence", payload=payload,
                                    create=create)

    def approve_exception(self, *, request_id: str, actor_id: str, exception_id: str,
                          finding_id: str, reason: str, expires_at: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "exception_id": exception_id,
                   "finding_id": finding_id, "reason": reason, "expires_at": expires_at}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            finding = connection.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if finding is None:
                raise NotFoundError("发现项不存在")
            candidate = self._candidate(connection, finding["candidate_id"])
            exception_id = self._identifier(exception_id, "exception_id")
            reason = self._text(reason, "reason")
            expires = self._parse_timestamp(expires_at, "expires_at")
            if expires <= self.clock.now():
                raise ValidationError("例外到期时间必须晚于当前时间")
            expires_text = self._timestamp_text(expires)

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO exception_approvals(exception_id,finding_id,candidate_id,"
                        "approver,reason,expires_at,status,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?,'active',?,?)",
                        (exception_id, finding_id, candidate["candidate_id"], actor_id,
                         reason, expires_text, actor_id, self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("例外批准编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="exception.approved",
                             resource_type="exception_approval", resource_id=exception_id,
                             detail={"candidate_id": candidate["candidate_id"],
                                     "finding_id": finding_id, "expires_at": expires_text},
                             occurred_at=self._now())
                return "exception_approval", exception_id, {
                    "exception_id": exception_id, "expires_at": expires_text,
                }

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.approve_exception", payload=payload,
                                    create=create)

    def revoke_exception(self, *, request_id: str, actor_id: str,
                         exception_id: str) -> GateWriteReceipt:
        payload = {"actor_id": actor_id, "exception_id": exception_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            exception = connection.execute(
                "SELECT * FROM exception_approvals WHERE exception_id=?", (exception_id,)
            ).fetchone()
            if exception is None:
                raise NotFoundError("例外批准不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                if exception["status"] != "active":
                    raise ConflictError("只有生效中的例外可以撤销")
                connection.execute(
                    "UPDATE exception_approvals SET status='revoked' WHERE exception_id=?",
                    (exception_id,),
                )
                candidate = self._candidate(connection, exception["candidate_id"])
                append_event(connection, actor_id=actor_id, action="exception.revoked",
                             resource_type="exception_approval", resource_id=exception_id,
                             detail={"candidate_id": exception["candidate_id"],
                                     "finding_id": exception["finding_id"]},
                             occurred_at=self._now())
                self._invalidate_live_approval(
                    connection, candidate=candidate,
                    reason_code="exception_revoked",
                    reason_message=f"发现项 {exception['finding_id']} 的例外批准 {exception_id} 已撤销",
                    refs={"exception_id": exception_id, "finding_id": exception["finding_id"]},
                    actor_id=actor_id,
                )
                return "exception_approval", exception_id, {"exception_id": exception_id,
                                                            "status": "revoked"}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.revoke_exception", payload=payload,
                                    create=create)

    def reopen_finding(self, *, request_id: str, actor_id: str, finding_id: str,
                       reason: str) -> GateWriteReceipt:
        """重新打开发现项：任何生效批准立即失效，例外不再覆盖该发现项。"""

        payload = {"actor_id": actor_id, "finding_id": finding_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            finding = connection.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if finding is None:
                raise NotFoundError("发现项不存在")
            candidate = self._candidate(connection, finding["candidate_id"])
            reason = self._text(reason, "reason")

            def create() -> tuple[str, str, dict[str, Any]]:
                if finding["status"] == "reopened":
                    raise ConflictError("发现项已经处于重新打开状态")
                now = self._now()
                connection.execute(
                    "UPDATE findings SET status='reopened', updated_at=? WHERE finding_id=?",
                    (now, finding_id),
                )
                append_event(connection, actor_id=actor_id, action="finding.reopened",
                             resource_type="finding", resource_id=finding_id,
                             detail={"candidate_id": candidate["candidate_id"],
                                     "blocking": bool(finding["blocking"]),
                                     "reason": reason},
                             occurred_at=now)
                if finding["blocking"]:
                    self._invalidate_live_approval(
                        connection, candidate=candidate,
                        reason_code="finding_reopened",
                        reason_message=f"阻断级发现项 {finding_id} 被重新打开：{reason}",
                        refs={"finding_id": finding_id, "reason": reason},
                        actor_id=actor_id,
                    )
                return "finding", finding_id, {"finding_id": finding_id, "status": "reopened"}

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.reopen_finding", payload=payload,
                                    create=create)

    # ------------------------------------------------------------- 门禁评估

    def _sweep_expired_exceptions(self, connection, candidate) -> list[str]:
        """把已到期但仍标记 active 的例外置为 expired，返回受影响的例外编号。"""

        now_text = self._timestamp_text(self.clock.now())
        rows = connection.execute(
            "SELECT exception_id, finding_id FROM exception_approvals "
            "WHERE candidate_id=? AND status='active' AND expires_at<=?",
            (candidate["candidate_id"], now_text),
        ).fetchall()
        expired = [row["exception_id"] for row in rows]
        if expired:
            connection.execute(
                "UPDATE exception_approvals SET status='expired' "
                "WHERE candidate_id=? AND status='active' AND expires_at<=?",
                (candidate["candidate_id"], now_text),
            )
            for row in rows:
                append_event(connection, actor_id="system", action="exception.expired",
                             resource_type="exception_approval",
                             resource_id=row["exception_id"],
                             detail={"candidate_id": candidate["candidate_id"],
                                     "finding_id": row["finding_id"]},
                             occurred_at=now_text)
        return expired

    def _compute_snapshot(self, connection, candidate) -> dict[str, Any]:
        """读取候选版本的完整门禁状态并计算阻断依据。该函数只读。"""

        version = candidate["version"]
        candidate_id = candidate["candidate_id"]
        now = self.clock.now()

        checks: list[dict[str, Any]] = []
        blocking_reasons: list[BlockingReason] = []
        for family in REQUIRED_CHECK_FAMILIES:
            batch = connection.execute(
                "SELECT * FROM evaluation_batches WHERE candidate_id=? AND check_family=? "
                "ORDER BY rowid DESC LIMIT 1",
                (candidate_id, family),
            ).fetchone()
            if batch is None:
                checks.append({"check_family": family, "status": "missing",
                               "batch_id": None, "version_pin": None,
                               "completed_at": None})
                blocking_reasons.append(BlockingReason(
                    code="check_missing",
                    message=f"检查族 {family} 尚未在候选版本 {version} 上登记评估批次",
                    recovery=f"在版本 {version} 上提交并完成 {family} 评估批次后重试",
                    refs={"check_family": family, "required_version": version},
                ))
            elif not batch["completed"]:
                checks.append({"check_family": family, "status": "incomplete",
                               "batch_id": batch["batch_id"],
                               "version_pin": batch["version_pin"],
                               "completed_at": None})
                blocking_reasons.append(BlockingReason(
                    code="check_incomplete",
                    message=f"检查族 {family} 的最新批次 {batch['batch_id']} 尚未完成",
                    recovery=f"完成批次 {batch['batch_id']}（固定在版本 {version}）后重试",
                    refs={"check_family": family, "batch_id": batch["batch_id"],
                          "required_version": version},
                ))
            elif batch["version_pin"] != version:
                checks.append({"check_family": family, "status": "version_mismatch",
                               "batch_id": batch["batch_id"],
                               "version_pin": batch["version_pin"],
                               "completed_at": batch["completed_at"]})
                blocking_reasons.append(BlockingReason(
                    code="check_version_mismatch",
                    message=f"检查族 {family} 完成在版本 {batch['version_pin']} 上，"
                            f"与候选版本 {version} 不一致",
                    recovery=f"在版本 {version} 上重新完成 {family} 评估批次",
                    refs={"check_family": family, "batch_id": batch["batch_id"],
                          "evaluated_version": batch["version_pin"],
                          "required_version": version},
                ))
            else:
                checks.append({"check_family": family, "status": "complete",
                               "batch_id": batch["batch_id"],
                               "version_pin": batch["version_pin"],
                               "completed_at": batch["completed_at"]})

        findings: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        finding_rows = connection.execute(
            "SELECT * FROM findings WHERE candidate_id=? ORDER BY created_at, finding_id",
            (candidate_id,),
        ).fetchall()
        for finding in finding_rows:
            evidence_rows = connection.execute(
                "SELECT * FROM remediation_evidence WHERE finding_id=? ORDER BY created_at, evidence_id",
                (finding["finding_id"],),
            ).fetchall()
            same_version_evidence = [row["evidence_id"] for row in evidence_rows
                                     if row["version_pin"] == version]
            other_version_evidence = [
                {"evidence_id": row["evidence_id"], "version_pin": row["version_pin"]}
                for row in evidence_rows if row["version_pin"] != version
            ]
            exception_rows = connection.execute(
                "SELECT * FROM exception_approvals WHERE finding_id=? ORDER BY created_at, exception_id",
                (finding["finding_id"],),
            ).fetchall()
            valid_exceptions = []
            invalid_exceptions = []
            for exc in exception_rows:
                item = {"exception_id": exc["exception_id"], "status": exc["status"],
                        "expires_at": exc["expires_at"], "created_at": exc["created_at"]}
                expires = self._parse_timestamp(exc["expires_at"], "expires_at")
                if exc["status"] == "active" and expires > now:
                    valid_exceptions.append(item)
                else:
                    invalid_exceptions.append(item)

            entry = {
                "finding_id": finding["finding_id"],
                "batch_id": finding["batch_id"],
                "check_family": finding["check_family"],
                "severity": finding["severity"],
                "title": finding["title"],
                "status": finding["status"],
                "blocking": bool(finding["blocking"]),
                "same_version_evidence": same_version_evidence,
                "other_version_evidence": other_version_evidence,
                "valid_exceptions": valid_exceptions,
                "invalid_exceptions": invalid_exceptions,
            }
            findings.append(entry)

            if not finding["blocking"]:
                continue
            refs = {"finding_id": finding["finding_id"], "severity": finding["severity"],
                    "required_version": version}
            if finding["status"] == "reopened":
                # 重新打开表示旧修复失效；但重新打开之后新批准的有效例外可以再次承担风险。
                post_reopen_exceptions = [
                    item for item in valid_exceptions
                    if item["created_at"] >= finding["updated_at"]
                ]
                if post_reopen_exceptions:
                    continue
                blocking_reasons.append(BlockingReason(
                    code="finding_reopened",
                    message=f"阻断级发现项 {finding['finding_id']} 已被重新打开，"
                            "既有修复与旧例外不再视为有效",
                    recovery=f"在版本 {version} 上重新修复并提交同版本复测证据，"
                             "或由管理员就重新打开的事实再次批准例外，然后重新申请发布决定",
                    refs={**refs, "reopened_at": finding["updated_at"]},
                ))
                unresolved.append(entry)
            elif same_version_evidence:
                # 同版本修复证据齐备，阻断解除。
                continue
            elif other_version_evidence:
                blocking_reasons.append(BlockingReason(
                    code="evidence_version_mismatch",
                    message=f"发现项 {finding['finding_id']} 的修复证据不在候选版本 {version} 上",
                    recovery=f"补充固定在版本 {version} 的修复/复测证据；"
                             "其他版本的证据不能解除本版本阻断",
                    refs={**refs, "evidence_on_other_versions": other_version_evidence},
                ))
                unresolved.append(entry)
            elif valid_exceptions:
                # 有效例外承担残余风险，阻断解除。
                continue
            else:
                detail = "且无有效例外批准" if not exception_rows else "但例外未生效（已撤销或已到期）"
                blocking_reasons.append(BlockingReason(
                    code="finding_open",
                    message=f"阻断级发现项 {finding['finding_id']} 尚未在版本 {version} 上缓解{detail}",
                    recovery=f"在版本 {version} 上提交修复/复测证据，或取得未到期的例外批准",
                    refs={**refs, "exceptions": invalid_exceptions},
                ))
                unresolved.append(entry)

        digest_material = {
            "candidate_id": candidate_id,
            "version": version,
            "checks": [{k: c[k] for k in ("check_family", "status", "batch_id",
                                          "version_pin", "completed_at")} for c in checks],
            "findings": [{
                "finding_id": f["finding_id"],
                "status": f["status"],
                "severity": f["severity"],
                "blocking": f["blocking"],
                "same_version_evidence": f["same_version_evidence"],
                "other_version_evidence": f["other_version_evidence"],
                "valid_exceptions": f["valid_exceptions"],
                "invalid_exceptions": f["invalid_exceptions"],
            } for f in findings],
        }
        check_summary = {
            c["check_family"]: {k: c[k] for k in ("status", "batch_id", "version_pin")}
            for c in checks
        }
        return {
            "checks": checks,
            "findings": findings,
            "unresolved": unresolved,
            "blocking_reasons": blocking_reasons,
            "basis_digest": digest(digest_material),
            "check_summary": check_summary,
        }

    def explain_gate(self, candidate_id: str) -> GateEvaluation:
        """说明候选版本当前为何被阻止（或为何满足），并先处理到期失效。"""

        candidate_id = self._identifier(candidate_id, "candidate_id")
        with self.database.transaction(immediate=True) as connection:
            candidate = self._candidate(connection, candidate_id)
            expired = self._sweep_expired_exceptions(connection, candidate)
            if expired:
                self._invalidate_live_approval(
                    connection, candidate=candidate,
                    reason_code="exception_expired",
                    reason_message=f"例外批准 {', '.join(expired)} 已到期",
                    refs={"exception_ids": expired},
                    actor_id="system",
                )
            snapshot = self._compute_snapshot(connection, candidate)
            return GateEvaluation(
                candidate_id=candidate["candidate_id"],
                model_id=candidate["model_id"],
                version=candidate["version"],
                satisfied=not snapshot["blocking_reasons"],
                checked_at=self._now(),
                checks=snapshot["checks"],
                unresolved_findings=snapshot["unresolved"],
                exceptions=[
                    item for f in snapshot["findings"]
                    for item in (f["valid_exceptions"] + f["invalid_exceptions"])
                ],
                blocking_reasons=snapshot["blocking_reasons"],
            )

    # ------------------------------------------------------------- 发布决定

    def _live_decision(self, connection, candidate_id: str):
        return connection.execute(
            "SELECT * FROM release_decisions WHERE candidate_id=? "
            "AND superseded_by_decision_id IS NULL AND invalidated_at IS NULL",
            (candidate_id,),
        ).fetchone()

    def _invalidate_live_approval(self, connection, *, candidate, reason_code: str,
                                  reason_message: str, refs: dict[str, Any],
                                  actor_id: str) -> None:
        """使当前生效的批准决定失效；被拒绝/已失效的决定不受影响，历史行保留。"""

        live = self._live_decision(connection, candidate["candidate_id"])
        if live is None or live["result"] != DECISION_APPROVED:
            return
        now = self._now()
        connection.execute(
            "UPDATE release_decisions SET invalidated_by=?, invalidated_reason=?, "
            "invalidated_at=? WHERE decision_id=?",
            (actor_id, reason_code, now, live["decision_id"]),
        )
        append_event(connection, actor_id=actor_id, action="release_decision.invalidated",
                     resource_type="release_decision", resource_id=live["decision_id"],
                     detail={"candidate_id": candidate["candidate_id"],
                             "reason_code": reason_code, "reason_message": reason_message,
                             "refs": refs},
                     occurred_at=now)

    def generate_decision(self, *, request_id: str, actor_id: str, candidate_id: str,
                          rationale: str = "") -> GateWriteReceipt:
        """依据当前快照生成发布决定；状态未变时复用既有生效决定。"""

        payload = {"actor_id": actor_id, "candidate_id": candidate_id, "rationale": rationale}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            candidate = self._candidate(connection, candidate_id)
            rationale = str(rationale or "").strip()
            rationale = rationale[:500]

            def create() -> tuple[str, str, dict[str, Any]]:
                expired = self._sweep_expired_exceptions(connection, candidate)
                if expired:
                    self._invalidate_live_approval(
                        connection, candidate=candidate,
                        reason_code="exception_expired",
                        reason_message=f"例外批准 {', '.join(expired)} 已到期",
                        refs={"exception_ids": expired},
                        actor_id="system",
                    )
                snapshot = self._compute_snapshot(connection, candidate)
                satisfied = not snapshot["blocking_reasons"]
                result = DECISION_APPROVED if satisfied else DECISION_REJECTED
                reasons = [{"code": r.code, "message": r.message, "recovery": r.recovery,
                            "refs": r.refs} for r in snapshot["blocking_reasons"]]
                default_rationale = (
                    "所有必需检查在同一候选版本上完成，阻断项均已缓解或持有有效例外"
                    if satisfied else "门禁仍有未满足条件，发布被阻止"
                )

                live = self._live_decision(connection, candidate["candidate_id"])
                if live is not None and live["basis_digest"] == snapshot["basis_digest"]:
                    # 状态依据未变化：复用既有生效决定，绝不重复制造互相矛盾的决定。
                    return "release_decision", live["decision_id"], {
                        "decision_id": live["decision_id"], "result": live["result"],
                        "reused": True,
                    }

                decision_id = uuid.uuid4().hex
                # 谱系上链接到最近一条决定（含已失效的批准）；若最近决定仍生效，
                # 先把它标记为被取代以释放唯一“生效槽位”，再插入新决定。
                predecessor = connection.execute(
                    "SELECT * FROM release_decisions WHERE candidate_id=? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (candidate_id,),
                ).fetchone()
                predecessor_live = (
                    predecessor is not None
                    and predecessor["superseded_by_decision_id"] is None
                    and predecessor["invalidated_at"] is None
                )
                if predecessor_live:
                    # 指向尚不存在的新行；自引用外键为延迟约束，提交时才检查。
                    connection.execute(
                        "UPDATE release_decisions SET superseded_by_decision_id=? "
                        "WHERE decision_id=?",
                        (decision_id, predecessor["decision_id"]),
                    )
                supersedes = predecessor["decision_id"] if predecessor is not None else None
                try:
                    connection.execute(
                        "INSERT INTO release_decisions(decision_id,candidate_id,result,"
                        "basis_candidate_version,basis_digest,rationale,blocking_reasons_json,"
                        "check_summary_json,supersedes_decision_id,superseded_by_decision_id,"
                        "invalidated_by,invalidated_reason,created_by,created_at,invalidated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,?,?,NULL)",
                        (decision_id, candidate["candidate_id"], result, candidate["version"],
                         snapshot["basis_digest"], rationale or default_rationale,
                         canonical_json(reasons), canonical_json(snapshot["check_summary"]),
                         supersedes, actor_id, self._now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ConflictError("该候选版本已存在生效决定，并发生成冲突，请重试") from exc

                if predecessor_live:
                    append_event(connection, actor_id=actor_id,
                                 action="release_decision.superseded",
                                 resource_type="release_decision",
                                 resource_id=predecessor["decision_id"],
                                 detail={"candidate_id": candidate["candidate_id"],
                                         "by_decision_id": decision_id},
                                 occurred_at=self._now())

                # 记录决定所依据的具体批次、发现项、证据与例外。
                for check in snapshot["checks"]:
                    if check["batch_id"]:
                        connection.execute(
                            "INSERT OR IGNORE INTO decision_basis_items(decision_id,item_type,item_id) "
                            "VALUES(?,?,?)",
                            (decision_id, "evaluation_batch", check["batch_id"]),
                        )
                for finding in snapshot["findings"]:
                    connection.execute(
                        "INSERT OR IGNORE INTO decision_basis_items(decision_id,item_type,item_id) "
                        "VALUES(?,?,?)",
                        (decision_id, "finding", finding["finding_id"]),
                    )
                    for evidence_id in finding["same_version_evidence"]:
                        connection.execute(
                            "INSERT OR IGNORE INTO decision_basis_items(decision_id,item_type,item_id) "
                            "VALUES(?,?,?)",
                            (decision_id, "remediation_evidence", evidence_id),
                        )
                    for exc in finding["valid_exceptions"]:
                        connection.execute(
                            "INSERT OR IGNORE INTO decision_basis_items(decision_id,item_type,item_id) "
                            "VALUES(?,?,?)",
                            (decision_id, "exception_approval", exc["exception_id"]),
                        )

                append_event(connection, actor_id=actor_id, action="release_decision.generated",
                             resource_type="release_decision", resource_id=decision_id,
                             detail={"candidate_id": candidate["candidate_id"], "result": result,
                                     "basis_digest": snapshot["basis_digest"],
                                     "supersedes": supersedes,
                                     "blocking_reason_codes": [r["code"] for r in reasons]},
                             occurred_at=self._now())
                return "release_decision", decision_id, {
                    "decision_id": decision_id, "result": result, "reused": False,
                }

            return self._idempotent(connection, request_id=request_id,
                                    action="gate.generate_decision", payload=payload,
                                    create=create)

    def _decision_from_row(self, row) -> tuple[ReleaseDecision, str]:
        if row["invalidated_at"]:
            state = DECISION_INVALIDATED
        elif row["superseded_by_decision_id"]:
            state = DECISION_SUPERSEDED
        else:
            state = row["result"]
        return ReleaseDecision(
            decision_id=row["decision_id"],
            candidate_id=row["candidate_id"],
            result=row["result"],
            basis_candidate_version=row["basis_candidate_version"],
            basis_digest=row["basis_digest"],
            rationale=row["rationale"],
            blocking_reasons=json.loads(row["blocking_reasons_json"]),
            check_summary=json.loads(row["check_summary_json"]),
            supersedes_decision_id=row["supersedes_decision_id"],
            invalidated_by=row["invalidated_by"],
            invalidated_reason=row["invalidated_reason"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            invalidated_at=row["invalidated_at"],
        ), state

    def get_decision(self, decision_id: str) -> dict[str, Any]:
        decision_id = self._identifier(decision_id, "decision_id")
        row = self.database.connection.execute(
            "SELECT * FROM release_decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("发布决定不存在")
        decision, state = self._decision_from_row(row)
        return {**decision.__dict__, "state": state}

    def list_decisions(self, candidate_id: str) -> list[dict[str, Any]]:
        candidate_id = self._identifier(candidate_id, "candidate_id")
        rows = self.database.connection.execute(
            "SELECT * FROM release_decisions WHERE candidate_id=? ORDER BY rowid",
            (candidate_id,),
        ).fetchall()
        result = []
        for row in rows:
            decision, state = self._decision_from_row(row)
            result.append({**decision.__dict__, "state": state})
        return result

    def current_status(self, candidate_id: str) -> dict[str, Any]:
        """汇总门禁说明与当前生效/最近失效决定，供 API 一次说明阻止依据。"""

        evaluation = self.explain_gate(candidate_id)
        decisions = self.list_decisions(candidate_id)
        live = next((d for d in decisions if d["state"] in (DECISION_APPROVED,
                                                            DECISION_REJECTED)), None)
        last_invalidated = next(
            (d for d in reversed(decisions) if d["state"] == DECISION_INVALIDATED), None
        )
        return {
            "evaluation": self._evaluation_dict(evaluation),
            "live_decision": None if live is None else {
                "decision_id": live["decision_id"], "state": live["state"],
                "created_at": live["created_at"], "created_by": live["created_by"],
                "basis_digest": live["basis_digest"],
                "basis_candidate_version": live["basis_candidate_version"],
            },
            "last_invalidated_decision": None if last_invalidated is None else {
                "decision_id": last_invalidated["decision_id"],
                "result": last_invalidated["result"],
                "invalidated_by": last_invalidated["invalidated_by"],
                "invalidated_reason": last_invalidated["invalidated_reason"],
                "invalidated_at": last_invalidated["invalidated_at"],
                "recovery": "按 blocking_reasons 消除阻断后，重新申请发布决定",
            },
            "decision_history_count": len(decisions),
        }

    def _evaluation_dict(self, evaluation: GateEvaluation) -> dict[str, Any]:
        return {
            "candidate_id": evaluation.candidate_id,
            "model_id": evaluation.model_id,
            "version": evaluation.version,
            "satisfied": evaluation.satisfied,
            "checked_at": evaluation.checked_at,
            "checks": evaluation.checks,
            "unresolved_findings": evaluation.unresolved_findings,
            "exceptions": evaluation.exceptions,
            "blocking_reasons": [r.__dict__ for r in evaluation.blocking_reasons],
        }

    # ------------------------------------------------------------- 读取视图

    def get_candidate(self, candidate_id: str) -> ReleaseCandidate:
        candidate_id = self._identifier(candidate_id, "candidate_id")
        row = self.database.connection.execute(
            "SELECT * FROM release_candidates WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("发布候选版本不存在")
        return ReleaseCandidate(row["candidate_id"], row["model_id"], row["version"],
                                row["created_by"], row["created_at"])

    def list_findings(self, candidate_id: str) -> list[Finding]:
        candidate_id = self._identifier(candidate_id, "candidate_id")
        self._candidate(self.database.connection, candidate_id)
        rows = self.database.connection.execute(
            "SELECT * FROM findings WHERE candidate_id=? ORDER BY created_at, finding_id",
            (candidate_id,),
        ).fetchall()
        return [Finding(row["finding_id"], row["batch_id"], row["candidate_id"],
                        row["check_family"], row["severity"], row["title"], row["status"],
                        bool(row["blocking"]), row["created_by"], row["created_at"],
                        row["updated_at"]) for row in rows]

    def list_exceptions(self, candidate_id: str) -> list[ExceptionApproval]:
        candidate_id = self._identifier(candidate_id, "candidate_id")
        rows = self.database.connection.execute(
            "SELECT * FROM exception_approvals WHERE candidate_id=? ORDER BY created_at, exception_id",
            (candidate_id,),
        ).fetchall()
        return [ExceptionApproval(row["exception_id"], row["finding_id"], row["candidate_id"],
                                  row["approver"], row["reason"], row["expires_at"],
                                  row["status"], row["created_by"], row["created_at"])
                for row in rows]
