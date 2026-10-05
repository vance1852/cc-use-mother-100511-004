import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_governance_foundation.api import route
from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, PermissionDenied, ValidationError
from ai_governance_foundation.release_gate import ReleaseGateService
from ai_governance_foundation.storage import Database

BASE_TIME = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
FUTURE = "2027-01-01T00:00:00Z"


class MutableClock:
    def __init__(self, value):
        self._value = value

    def now(self):
        return self._value

    def advance(self, **kwargs):
        self._value = self._value + timedelta(**kwargs)


class ReleaseGateTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = MutableClock(BASE_TIME)
        self.service = ReleaseGateService(self.database, self.clock)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                    display_name="发布经理", role="operator", organization_id="o1")
        self.service.register_actor(request_id="reviewer", actor_id="a1", new_actor_id="sec1",
                                    display_name="安全评估员", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="auditor", actor_id="a1", new_actor_id="au1",
                                    display_name="审计员", role="auditor", organization_id="o1")
        self._request_counter = 0

    def tearDown(self):
        self.database.close()

    def _req(self, prefix):
        self._request_counter += 1
        return f"{prefix}-{self._request_counter}"

    def _candidate(self, candidate_id="cand-1", version="2.1.0-rc.1"):
        return self.service.register_candidate(
            request_id=self._req("candidate"), actor_id="op1", candidate_id=candidate_id,
            model_name="fraud-detector", version=version)["candidate_id"]

    def _batch(self, candidate_id, check_type, complete=True):
        batch_id = self.service.submit_batch(
            request_id=self._req("batch"), actor_id="sec1",
            candidate_id=candidate_id, check_type=check_type)["batch_id"]
        if complete:
            self.service.complete_batch(request_id=self._req("complete"),
                                        actor_id="sec1", batch_id=batch_id)
        return batch_id

    def _complete_all_checks(self, candidate_id):
        return {check_type: self._batch(candidate_id, check_type)
                for check_type in ("vulnerability", "permission", "data_leak")}

    def _finding(self, batch_id, severity="critical", title="越权访问"):
        return self.service.add_finding(
            request_id=self._req("finding"), actor_id="sec1", batch_id=batch_id,
            severity=severity, title=title, description="评估发现的细节")["finding_id"]

    def _decide(self, candidate_id="cand-1", request_id=None):
        return self.service.generate_decision(
            request_id=request_id or self._req("decision"), actor_id="op1",
            candidate_id=candidate_id)

    # ---------- 门禁规则 ----------

    def test_blocked_when_required_checks_missing(self):
        self._candidate()
        decision = self._decide()
        self.assertEqual("blocked", decision["outcome"])
        codes = [item["code"] for item in decision["blockers"]]
        self.assertEqual(["missing_completed_check"] * 3, codes)
        for blocker in decision["blockers"]:
            self.assertIn("recovery", blocker)
            self.assertIn("评估批次", blocker["recovery"])

    def test_checks_completed_on_other_version_do_not_count(self):
        self._candidate("cand-1", "2.1.0-rc.1")
        self._complete_all_checks("cand-1")
        self.assertEqual("approved", self._decide("cand-1")["outcome"])
        self._candidate("cand-2", "2.1.0-rc.2")
        decision = self._decide("cand-2")
        self.assertEqual("blocked", decision["outcome"])
        self.assertEqual(3, len(decision["blockers"]))

    def test_open_batch_does_not_satisfy_check(self):
        self._candidate()
        self._batch("cand-1", "vulnerability", complete=False)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        decision = self._decide()
        self.assertEqual("blocked", decision["outcome"])
        codes = [item["code"] for item in decision["blockers"]]
        self.assertEqual(["missing_completed_check"], codes)
        self.assertEqual("vulnerability", decision["blockers"][0]["check_type"])

    def test_unresolved_critical_finding_blocks_then_exception_approves(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        blocked = self._decide()
        self.assertEqual("blocked", blocked["outcome"])
        self.assertEqual("finding_unresolved", blocked["blockers"][0]["code"])
        self.assertEqual(finding_id, blocked["blockers"][0]["finding_id"])
        exception = self.service.approve_exception(
            request_id=self._req("exception"), actor_id="a1", finding_id=finding_id,
            reason="风险已评审，灰度期间接受", valid_until=FUTURE)
        approved = self._decide()
        self.assertEqual("approved", approved["outcome"])
        self.assertEqual([exception["exception_id"]], approved["relied_exception_ids"])

    def test_resolved_finding_allows_approval(self):
        self._candidate()
        batch_id = self._batch("cand-1", "data_leak", complete=False)
        finding_id = self._finding(batch_id, severity="high", title="训练数据外发")
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "vulnerability")
        self._batch("cand-1", "permission")
        self.assertEqual("blocked", self._decide()["outcome"])
        resolved = self.service.resolve_finding(
            request_id=self._req("resolve"), actor_id="sec1", finding_id=finding_id,
            summary="已加外发拦截", artifact_uri="https://evidence.internal/fix/1")
        self.assertEqual("resolved", resolved["status"])
        self.assertTrue(resolved["evidence_id"])
        self.assertEqual("approved", self._decide()["outcome"])

    def test_expired_exception_blocks_new_decision(self):
        self._candidate()
        batch_id = self._batch("cand-1", "permission", complete=False)
        finding_id = self._finding(batch_id, severity="medium", title="令牌过期策略缺失")
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "vulnerability")
        self._batch("cand-1", "data_leak")
        self.service.approve_exception(
            request_id=self._req("exception"), actor_id="a1", finding_id=finding_id,
            reason="短期接受", valid_until="2026-10-02T00:00:00Z")
        self.assertEqual("approved", self._decide()["outcome"])
        self.clock.advance(days=3)
        decision = self._decide()
        self.assertEqual("blocked", decision["outcome"])
        self.assertEqual("exception_expired", decision["blockers"][0]["code"])

    # ---------- 失效与历史 ----------

    def test_critical_reopen_invalidates_approval_and_keeps_history(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        self.service.resolve_finding(request_id=self._req("resolve"), actor_id="sec1",
                                     finding_id=finding_id, summary="已修复",
                                     artifact_uri="https://evidence.internal/fix/2")
        approved = self._decide()
        self.assertEqual("approved", approved["outcome"])

        reopened = self.service.reopen_finding(request_id=self._req("reopen"), actor_id="sec1",
                                               finding_id=finding_id, reason="回归测试复现")
        self.assertEqual([approved["decision_id"]], reopened["invalidated_decision_ids"])

        current = self.service.current_decision("cand-1")
        self.assertFalse(current["valid"])
        self.assertEqual("approved", current["decision"]["outcome"])
        self.assertEqual("critical_finding_reopened", current["invalidation"]["reason_code"])
        self.assertEqual(finding_id, current["invalidation"]["detail"]["finding_id"])
        self.assertEqual("finding_unresolved", current["current_blockers"][0]["code"])

        history = self.service.list_decisions("cand-1")
        self.assertEqual(1, len(history))
        self.assertEqual("approved", history[0]["outcome"])
        self.assertTrue(history[0]["invalidated"])

        blocked = self._decide()
        self.assertEqual("blocked", blocked["outcome"])
        self.service.resolve_finding(request_id=self._req("resolve2"), actor_id="sec1",
                                     finding_id=finding_id, summary="再次修复并补回归",
                                     artifact_uri="https://evidence.internal/fix/3")
        final = self._decide()
        self.assertEqual("approved", final["outcome"])
        self.assertTrue(self.service.current_decision("cand-1")["valid"])
        self.assertEqual(3, len(self.service.list_decisions("cand-1")))

    def test_noncritical_reopen_keeps_approval_but_blocks_new_decision(self):
        self._candidate()
        batch_id = self._batch("cand-1", "data_leak", complete=False)
        finding_id = self._finding(batch_id, severity="medium", title="日志含敏感字段")
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "vulnerability")
        self._batch("cand-1", "permission")
        self.service.resolve_finding(request_id=self._req("resolve"), actor_id="sec1",
                                     finding_id=finding_id, summary="已脱敏",
                                     artifact_uri="https://evidence.internal/fix/4")
        self._decide()
        reopened = self.service.reopen_finding(request_id=self._req("reopen"), actor_id="sec1",
                                               finding_id=finding_id, reason="抽样发现遗漏")
        self.assertEqual([], reopened["invalidated_decision_ids"])
        self.assertTrue(self.service.current_decision("cand-1")["valid"])
        self.assertEqual("blocked", self._decide()["outcome"])

    def test_revoke_exception_invalidates_relying_approval(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        exception = self.service.approve_exception(
            request_id=self._req("exception"), actor_id="a1", finding_id=finding_id,
            reason="灰度接受", valid_until=FUTURE)
        self._decide()
        revoked = self.service.revoke_exception(
            request_id=self._req("revoke"), actor_id="a1",
            exception_id=exception["exception_id"], reason="风险评审结论变化")
        self.assertEqual(1, len(revoked["invalidated_decision_ids"]))
        current = self.service.current_decision("cand-1")
        self.assertFalse(current["valid"])
        self.assertEqual("exception_revoked", current["invalidation"]["reason_code"])

    def test_expired_exception_invalidates_existing_approval_lazily(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        self.service.approve_exception(
            request_id=self._req("exception"), actor_id="a1", finding_id=finding_id,
            reason="限期接受", valid_until="2026-10-02T00:00:00Z")
        self._decide()
        self.clock.advance(days=3)
        current = self.service.current_decision("cand-1")
        self.assertFalse(current["valid"])
        self.assertEqual("exception_expired", current["invalidation"]["reason_code"])
        history = self.service.list_decisions("cand-1")
        self.assertTrue(history[0]["invalidated"])

    # ---------- 幂等与冲突 ----------

    def test_decision_request_replays_same_result(self):
        self._candidate()
        self._complete_all_checks("cand-1")
        first = self._decide(request_id="decision-fixed")
        second = self._decide(request_id="decision-fixed")
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["decision_id"], second["decision_id"])
        self.assertEqual(1, len(self.service.list_decisions("cand-1")))

    def test_request_id_rejects_changed_payload(self):
        self._candidate()
        self._complete_all_checks("cand-1")
        self._decide(request_id="decision-fixed")
        self._candidate("cand-2", "2.1.0-rc.2")
        with self.assertRaises(ConflictError):
            self._decide("cand-2", request_id="decision-fixed")

    def test_completed_batch_rejects_new_findings_and_double_completion(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability")
        with self.assertRaises(ConflictError):
            self._finding(batch_id)
        with self.assertRaises(ConflictError):
            self.service.complete_batch(request_id=self._req("complete"),
                                        actor_id="sec1", batch_id=batch_id)

    def test_reopen_requires_resolved_finding(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        with self.assertRaises(ConflictError):
            self.service.reopen_finding(request_id=self._req("reopen"), actor_id="sec1",
                                        finding_id=finding_id, reason="尚未关闭")

    def test_exception_requires_future_valid_until(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        with self.assertRaises(ValidationError):
            self.service.approve_exception(
                request_id=self._req("exception"), actor_id="a1", finding_id=finding_id,
                reason="过期例外", valid_until="2026-09-01T00:00:00Z")

    # ---------- 权限 ----------

    def test_role_restrictions(self):
        self._candidate()
        with self.assertRaises(PermissionDenied):
            self.service.submit_batch(request_id=self._req("batch"), actor_id="au1",
                                      candidate_id="cand-1", check_type="vulnerability")
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        with self.assertRaises(PermissionDenied):
            self.service.approve_exception(request_id=self._req("exception"), actor_id="op1",
                                           finding_id=finding_id, reason="越权批准",
                                           valid_until=FUTURE)
        with self.assertRaises(PermissionDenied):
            self.service.generate_decision(request_id=self._req("decision"), actor_id="au1",
                                           candidate_id="cand-1")

    # ---------- 重启持久化 ----------

    def test_restart_preserves_decisions_idempotency_and_invalidations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.sqlite3"
            database = Database(path)
            service = ReleaseGateService(database, FixedClock(BASE_TIME))
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="科研机构一")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                   display_name="发布经理", role="operator", organization_id="o1")
            service.register_actor(request_id="reviewer", actor_id="a1", new_actor_id="sec1",
                                   display_name="安全评估员", role="reviewer", organization_id="o1")
            service.register_candidate(request_id="candidate", actor_id="op1",
                                       candidate_id="cand-1", model_name="fraud-detector",
                                       version="2.1.0-rc.1")
            for check_type in ("vulnerability", "permission", "data_leak"):
                batch = service.submit_batch(request_id=f"batch-{check_type}", actor_id="sec1",
                                             candidate_id="cand-1", check_type=check_type)
                service.complete_batch(request_id=f"complete-{check_type}", actor_id="sec1",
                                       batch_id=batch["batch_id"])
            approved = service.generate_decision(request_id="decision-1", actor_id="op1",
                                                 candidate_id="cand-1")
            database.close()

            restarted = Database(path)
            service = ReleaseGateService(restarted, FixedClock(BASE_TIME))
            replay = service.generate_decision(request_id="decision-1", actor_id="op1",
                                               candidate_id="cand-1")
            self.assertTrue(replay["replayed"])
            self.assertEqual(approved["decision_id"], replay["decision_id"])
            self.assertTrue(service.current_decision("cand-1")["valid"])
            restarted.close()

            restarted = Database(path)
            service = ReleaseGateService(restarted, FixedClock(BASE_TIME))
            self.assertEqual(1, len(service.list_decisions("cand-1")))
            valid, _ = service.verify_audit()
            self.assertTrue(valid)
            restarted.close()

    # ---------- 并发 ----------

    def test_concurrent_decisions_and_reopen_never_contradict(self):
        self._candidate()
        batch_id = self._batch("cand-1", "vulnerability", complete=False)
        finding_id = self._finding(batch_id)
        self.service.complete_batch(request_id=self._req("complete"),
                                    actor_id="sec1", batch_id=batch_id)
        self._batch("cand-1", "permission")
        self._batch("cand-1", "data_leak")
        self.service.resolve_finding(request_id=self._req("resolve"), actor_id="sec1",
                                     finding_id=finding_id, summary="已修复",
                                     artifact_uri="https://evidence.internal/fix/5")

        errors = []

        def decide(index):
            try:
                self.service.generate_decision(request_id=f"concurrent-{index}",
                                               actor_id="op1", candidate_id="cand-1")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def reopen():
            try:
                self.service.reopen_finding(request_id="concurrent-reopen", actor_id="sec1",
                                            finding_id=finding_id, reason="并发回归")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=decide, args=(index,)) for index in range(6)]
        threads.insert(3, threading.Thread(target=reopen))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual([], errors)
        history = self.service.list_decisions("cand-1")
        valid_approvals = [item for item in history
                           if item["outcome"] == "approved" and not item["invalidated"]]
        self.assertEqual([], valid_approvals)
        for item in history:
            if item["outcome"] == "approved":
                self.assertEqual("critical_finding_reopened",
                                 item["invalidation"]["reason_code"])
        valid, _ = self.service.verify_audit()
        self.assertTrue(valid)

    def test_concurrent_same_request_id_yields_single_decision(self):
        self._candidate()
        self._complete_all_checks("cand-1")
        results = []

        def decide():
            results.append(self.service.generate_decision(
                request_id="shared-request", actor_id="op1", candidate_id="cand-1"))

        threads = [threading.Thread(target=decide) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(2, len(results))
        self.assertEqual(results[0]["decision_id"], results[1]["decision_id"])
        self.assertEqual(sorted(item["replayed"] for item in results), [False, True])
        self.assertEqual(1, len(self.service.list_decisions("cand-1")))


class ReleaseGateApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = ReleaseGateService(self.database, FixedClock(BASE_TIME))
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                    display_name="发布经理", role="operator", organization_id="o1")

    def tearDown(self):
        self.database.close()

    def test_blocked_decision_explains_basis_and_recovery_over_api(self):
        status, _ = route(self.service, "POST", "/release-candidates",
                          {"request_id": "c1", "candidate_id": "cand-1",
                           "model_name": "fraud-detector", "version": "2.1.0-rc.1"},
                          {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        status, decision = route(self.service, "POST", "/release-decisions",
                                 {"request_id": "d1", "candidate_id": "cand-1"},
                                 {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("blocked", decision["outcome"])
        self.assertEqual(3, len(decision["blockers"]))
        self.assertTrue(all(item["recovery"] for item in decision["blockers"]))

        status, current = route(self.service, "GET",
                                "/release-decisions/current?candidate_id=cand-1", None)
        self.assertEqual(200, status)
        self.assertFalse(current["valid"])
        self.assertEqual(3, len(current["current_blockers"]))

        status, gate = route(self.service, "GET",
                             "/release-gate/status?candidate_id=cand-1", None)
        self.assertEqual(200, status)
        self.assertEqual("blocked", gate["outcome"])

    def test_decision_replay_returns_same_body_over_api(self):
        route(self.service, "POST", "/release-candidates",
              {"request_id": "c1", "candidate_id": "cand-1",
               "model_name": "fraud-detector", "version": "2.1.0-rc.1"},
              {"X-Actor-Id": "op1"})
        first = route(self.service, "POST", "/release-decisions",
                      {"request_id": "d1", "candidate_id": "cand-1"},
                      {"X-Actor-Id": "op1"})
        second = route(self.service, "POST", "/release-decisions",
                       {"request_id": "d1", "candidate_id": "cand-1"},
                       {"X-Actor-Id": "op1"})
        self.assertEqual(201, first[0])
        self.assertEqual(200, second[0])
        self.assertEqual(first[1]["decision_id"], second[1]["decision_id"])

    def test_gate_route_requires_candidate_id(self):
        status, payload = route(self.service, "GET", "/release-gate/status", None)
        self.assertEqual(400, status)
        self.assertEqual("validation_error", payload["error"])


if __name__ == "__main__":
    unittest.main()
