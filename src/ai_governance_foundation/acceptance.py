"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .release_gate import ReleaseGateService
from .storage import Database


def run() -> dict[str, object]:
    """执行一条完整登记链与发布门禁链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = ReleaseGateService(database, FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc)))
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_actor(request_id="req-reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                               display_name="安全评估员", role="reviewer", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})

        # 发布门禁链：候选版本 -> 三类评估 -> 关键发现 -> 阻断 -> 修复 -> 批准 -> 重开失效 -> 再修复 -> 再批准
        service.register_candidate(request_id="req-candidate", actor_id="operator-001",
                                   candidate_id="cand-001", model_name="fraud-detector",
                                   version="3.0.0-rc.1", note="发布委员会候选版本")
        batches = {}
        for index, check_type in enumerate(("vulnerability", "permission", "data_leak")):
            result = service.submit_batch(request_id=f"req-batch-{check_type}", actor_id="reviewer-001",
                                          candidate_id="cand-001", check_type=check_type)
            batches[check_type] = result["batch_id"]
        finding = service.add_finding(request_id="req-finding", actor_id="reviewer-001",
                                      batch_id=batches["vulnerability"], severity="critical",
                                      title="越权调用训练数据接口",
                                      description="模型服务账户可读取未授权数据集")
        for check_type, batch_id in batches.items():
            service.complete_batch(request_id=f"req-complete-{check_type}", actor_id="reviewer-001",
                                   batch_id=batch_id)
        blocked = service.generate_decision(request_id="req-decision-1", actor_id="operator-001",
                                            candidate_id="cand-001")
        service.resolve_finding(request_id="req-resolve", actor_id="reviewer-001",
                                finding_id=finding["finding_id"], summary="已收敛服务账户权限",
                                artifact_uri="https://evidence.internal/fix/PR-4821")
        approved = service.generate_decision(request_id="req-decision-2", actor_id="operator-001",
                                             candidate_id="cand-001")
        reopened = service.reopen_finding(request_id="req-reopen", actor_id="reviewer-001",
                                          finding_id=finding["finding_id"],
                                          reason="回归测试发现权限再次扩大")
        after_reopen = service.current_decision("cand-001")
        service.resolve_finding(request_id="req-resolve-2", actor_id="reviewer-001",
                                finding_id=finding["finding_id"], summary="增加权限回归测试并再次收敛",
                                artifact_uri="https://evidence.internal/fix/PR-4830")
        final = service.generate_decision(request_id="req-decision-3", actor_id="operator-001",
                                          candidate_id="cand-001")
        current = service.current_decision("cand-001")

        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed,
                  "gate": {
                      "first_decision": blocked["outcome"],
                      "first_blockers": [item["code"] for item in blocked["blockers"]],
                      "second_decision": approved["outcome"],
                      "reopen_invalidated": reopened["invalidated_decision_ids"] == [approved["decision_id"]],
                      "current_valid_after_reopen": after_reopen["valid"],
                      "final_decision": final["outcome"],
                      "current_valid_final": current["valid"],
                  }}
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    gate = result["gate"]
    gate_ok = (gate["first_decision"] == "blocked" and gate["second_decision"] == "approved"
               and gate["reopen_invalidated"] and not gate["current_valid_after_reopen"]
               and gate["final_decision"] == "approved" and gate["current_valid_final"])
    return 0 if result["status"] == "ok" and result["audit_valid"] and gate_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
