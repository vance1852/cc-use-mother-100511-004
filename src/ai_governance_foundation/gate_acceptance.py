"""运行模型发布门禁的离线端到端验收。

覆盖：评估未完成被阻止 → 关键发现 → 错误版本证据不解除阻断 → 同版本证据后批准
→ 发现项重新打开使旧批准失效（历史保留）→ 重新修复后再次批准；
并验证全过程审计哈希链完整、决定历史不被覆盖。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .clock import FixedClock
from .gate_models import DECISION_APPROVED, DECISION_INVALIDATED, DECISION_SUPERSEDED
from .gate_service import GateService
from .service import DomainService
from .storage import Database

FAMILIES = ("vulnerability", "permission", "data_leak")


def run() -> dict[str, object]:
    """执行一条完整的门禁决策链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "gate_acceptance.sqlite3")
        clock = FixedClock(datetime(2026, 10, 1, 8, tzinfo=timezone.utc))
        service = DomainService(database, clock)
        gate = GateService(database, clock)

        service.register_organization(request_id="org", actor_id="bootstrap",
                                      organization_id="org-001", name="发布委员会示范机构")
        service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="发布管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                               display_name="安全评审", role="reviewer", organization_id="org-001")
        service.register_actor(request_id="operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="修复负责人", role="operator", organization_id="org-001")

        version = "model-gpt-next-2026.10.01"
        gate.register_candidate(request_id="candidate", actor_id="admin-001",
                                candidate_id="candidate-001", model_id="model-gpt-next",
                                version=version)

        # 1. 评估未完成时，决定必须是拒绝，并给出具体依据与恢复条件。
        gate.register_batch(request_id="b-vuln", actor_id="reviewer-001", batch_id="batch-vuln",
                            candidate_id="candidate-001", check_family="vulnerability",
                            version_pin=version)
        gate.complete_batch(request_id="d-vuln", actor_id="reviewer-001", batch_id="batch-vuln")
        gate.register_batch(request_id="b-perm", actor_id="reviewer-001", batch_id="batch-perm",
                            candidate_id="candidate-001", check_family="permission",
                            version_pin=version)
        blocked = gate.generate_decision(request_id="decision-blocked", actor_id="admin-001",
                                         candidate_id="candidate-001")
        blocked_decision = gate.get_decision(blocked.resource_id)
        blocked_codes = [item["code"] for item in blocked_decision["blocking_reasons"]]

        # 2. 三个检查族全部在同一版本完成，但出现一个关键发现项。
        gate.complete_batch(request_id="d-perm", actor_id="reviewer-001", batch_id="batch-perm")
        gate.register_batch(request_id="b-leak", actor_id="reviewer-001", batch_id="batch-leak",
                            candidate_id="candidate-001", check_family="data_leak",
                            version_pin=version)
        gate.complete_batch(request_id="d-leak", actor_id="reviewer-001", batch_id="batch-leak")
        gate.record_finding(request_id="finding", actor_id="reviewer-001", finding_id="finding-001",
                            batch_id="batch-leak", severity="critical",
                            title="输出中可还原训练样本中的个人信息")
        with_finding = gate.generate_decision(request_id="decision-finding", actor_id="admin-001",
                                              candidate_id="candidate-001")
        with_finding_decision = gate.get_decision(with_finding.resource_id)

        # 3. 其他版本上的修复证据不能解除本版本阻断。
        gate.add_evidence(request_id="evidence-old", actor_id="operator-001",
                          evidence_id="evidence-old", finding_id="finding-001", kind="patch",
                          reference="https://example.test/patch-on-older-version",
                          version_pin="model-gpt-next-2026.09.15")
        mismatch = gate.explain_gate("candidate-001")
        mismatch_codes = [reason.code for reason in mismatch.blocking_reasons]

        # 4. 同版本复测证据齐备后批准发布。
        gate.add_evidence(request_id="evidence-new", actor_id="operator-001",
                          evidence_id="evidence-new", finding_id="finding-001", kind="retest",
                          reference="复测报告 RET-2026-1001", version_pin=version)
        approved = gate.generate_decision(request_id="decision-approved", actor_id="admin-001",
                                          candidate_id="candidate-001")
        approved_decision = gate.get_decision(approved.resource_id)

        # 5. 关键发现项被重新打开：旧批准失效而非被覆盖。
        gate.reopen_finding(request_id="reopen", actor_id="reviewer-001",
                            finding_id="finding-001", reason="复测再次还原出个人信息")
        after_reopen = gate.current_status("candidate-001")
        reopen_codes = [reason["code"]
                        for reason in after_reopen["evaluation"]["blocking_reasons"]]

        # 6. 同版本重新修复并复测，生成新的批准；历史链条完整。
        gate.add_evidence(request_id="evidence-final", actor_id="operator-001",
                          evidence_id="evidence-final", finding_id="finding-001",
                          kind="retest", reference="复测报告 RET-2026-1002",
                          version_pin=version)
        final = gate.generate_decision(request_id="decision-final", actor_id="admin-001",
                                       candidate_id="candidate-001")
        final_decision = gate.get_decision(final.resource_id)
        history = gate.list_decisions("candidate-001")
        states = [item["state"] for item in history]

        # 7. 推进时钟，演示例外到期路径（独立候选版本）。
        later = FixedClock(clock.now() + timedelta(days=2))
        gate.clock = later
        gate.register_candidate(request_id="candidate-2", actor_id="admin-001",
                                candidate_id="candidate-002", model_id="model-gpt-next",
                                version="model-gpt-next-2026.10.08")
        for family in FAMILIES:
            gate.register_batch(request_id=f"b2-{family}", actor_id="reviewer-001",
                                batch_id=f"batch2-{family}", candidate_id="candidate-002",
                                check_family=family, version_pin="model-gpt-next-2026.10.08")
            gate.complete_batch(request_id=f"d2-{family}", actor_id="reviewer-001",
                                batch_id=f"batch2-{family}")
        gate.record_finding(request_id="finding-2", actor_id="reviewer-001",
                            finding_id="finding-002", batch_id="batch2-permission",
                            severity="high", title="越权调用工具")
        expires_at = (clock.now() + timedelta(days=3)).isoformat().replace("+00:00", "Z")
        gate.approve_exception(request_id="exception", actor_id="admin-001",
                               exception_id="exception-001", finding_id="finding-002",
                               reason="委员会评审后承担残余风险", expires_at=expires_at)
        exception_decision = gate.generate_decision(request_id="decision-exception",
                                                     actor_id="admin-001",
                                                     candidate_id="candidate-002")
        gate.clock = FixedClock(clock.now() + timedelta(days=10))
        expired_status = gate.current_status("candidate-002")

        audit_valid, audit_events = service.verify_audit()
        database.close()

        checks = {
            "blocked_while_evaluation_incomplete": (
                blocked_decision["state"] == "rejected"
                and "check_incomplete" in blocked_codes and "check_missing" in blocked_codes
                and all(item.get("recovery") for item in blocked_decision["blocking_reasons"])
            ),
            "blocked_with_open_critical_finding": (
                with_finding_decision["state"] == "rejected"
                and with_finding_decision["blocking_reasons"][0]["code"] == "finding_open"
            ),
            "other_version_evidence_does_not_unblock": mismatch_codes == ["evidence_version_mismatch"],
            "approved_after_same_version_evidence": approved_decision["state"] == DECISION_APPROVED,
            "reopen_invalidates_old_approval": (
                after_reopen["last_invalidated_decision"]["decision_id"]
                == approved_decision["decision_id"]
                and reopen_codes == ["finding_reopened"]
                and after_reopen["live_decision"] is None
            ),
            "history_preserved_not_overwritten": (
                states == [DECISION_SUPERSEDED, DECISION_SUPERSEDED, DECISION_INVALIDATED,
                           DECISION_APPROVED]
                and history[2]["result"] == DECISION_APPROVED
                and final_decision["state"] == DECISION_APPROVED
            ),
            "active_exception_allows_then_expiry_blocks": (
                gate is not None
                and exception_decision.resource_id
                and expired_status["last_invalidated_decision"]["invalidated_reason"]
                == "exception_expired"
                and not expired_status["evaluation"]["satisfied"]
            ),
            "audit_chain_valid": audit_valid,
        }
        return {
            "status": "ok" if all(checks.values()) else "failed",
            "checks": checks,
            "decision_history": states,
            "decision_count": len(history),
            "audit_events": audit_events,
            "audit_valid": audit_valid,
        }


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
