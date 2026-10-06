import json
import tempfile
import threading
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

from ai_governance_foundation.api import Handler
from ai_governance_foundation.errors import PermissionDenied, ValidationError
from ai_governance_foundation.gate_models import (
    DECISION_APPROVED,
    DECISION_INVALIDATED,
    DECISION_REJECTED,
    DECISION_SUPERSEDED,
)
from ai_governance_foundation.gate_service import GateService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database

FAMILIES = ("vulnerability", "permission", "data_leak")


class GateTestBase(unittest.TestCase):
    clock = None

    def setUp(self):
        self.database = Database()
        if self.clock is None:
            self.clock = self.make_clock(2026, 10, 1, 8)
        self.service = DomainService(self.database, self.clock)
        self.gate = GateService(self.database, self.clock)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="治理机构")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="reviewer", actor_id="a1", new_actor_id="r1",
                                    display_name="评审", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                    display_name="操作员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="auditor", actor_id="a1", new_actor_id="au1",
                                    display_name="审计员", role="auditor", organization_id="o1")

    def tearDown(self):
        self.database.close()

    @staticmethod
    def make_clock(year, month, day, hour=0):
        from ai_governance_foundation.clock import FixedClock
        return FixedClock(datetime(year, month, day, hour, tzinfo=timezone.utc))

    def create_candidate(self, candidate_id="c1", version="2026.10.01"):
        self.gate.register_candidate(request_id=f"cand-{candidate_id}", actor_id="op1",
                                     candidate_id=candidate_id, model_id="model-x",
                                     version=version)
        return version

    def add_completed_batch(self, family, candidate_id="c1", version="2026.10.01",
                            batch_id=None, actor_id="r1"):
        batch_id = batch_id or f"b-{family}"
        self.gate.register_batch(request_id=f"batch-{batch_id}", actor_id=actor_id,
                                 batch_id=batch_id, candidate_id=candidate_id,
                                 check_family=family, version_pin=version)
        self.gate.complete_batch(request_id=f"done-{batch_id}", actor_id=actor_id,
                                 batch_id=batch_id)
        return batch_id

    def complete_all_checks(self, candidate_id="c1", version="2026.10.01"):
        for family in FAMILIES:
            self.add_completed_batch(family, candidate_id, version)

    def decision(self, candidate_id="c1", request_id="dec-1", actor_id="a1", rationale=""):
        receipt = self.gate.generate_decision(request_id=request_id, actor_id=actor_id,
                                              candidate_id=candidate_id, rationale=rationale)
        return self.gate.get_decision(receipt.resource_id)


class GateHappyPathTest(GateTestBase):
    def test_all_checks_on_same_version_allows_release(self):
        version = self.create_candidate()
        self.complete_all_checks(version=version)
        evaluation = self.gate.explain_gate("c1")
        self.assertTrue(evaluation.satisfied)
        self.assertEqual([], evaluation.blocking_reasons)
        decision = self.decision()
        self.assertEqual(DECISION_APPROVED, decision["state"])
        self.assertEqual(version, decision["basis_candidate_version"])
        self.assertEqual(set(FAMILIES), set(decision["check_summary"]))

    def test_missing_and_incomplete_checks_block_with_recovery(self):
        self.create_candidate()
        self.add_completed_batch("vulnerability")
        self.gate.register_batch(request_id="batch-b-permission", actor_id="r1",
                                 batch_id="b-permission", candidate_id="c1",
                                 check_family="permission", version_pin="2026.10.01")
        evaluation = self.gate.explain_gate("c1")
        self.assertFalse(evaluation.satisfied)
        codes = {reason.code for reason in evaluation.blocking_reasons}
        self.assertEqual({"check_incomplete", "check_missing"}, codes)
        for reason in evaluation.blocking_reasons:
            self.assertTrue(reason.recovery)
            self.assertIn("2026.10.01", reason.recovery)
        decision = self.decision()
        self.assertEqual(DECISION_REJECTED, decision["state"])
        stored_codes = {item["code"] for item in decision["blocking_reasons"]}
        self.assertEqual(codes, stored_codes)

    def test_batch_pinned_to_other_version_is_rejected_upfront(self):
        self.create_candidate(version="2026.10.01")
        with self.assertRaises(ValidationError):
            self.gate.register_batch(request_id="batch-x", actor_id="r1", batch_id="b-x",
                                     candidate_id="c1", check_family="permission",
                                     version_pin="2026.09.01")


class FindingGateTest(GateTestBase):
    def prepare(self):
        version = self.create_candidate()
        self.complete_all_checks(version=version)
        self.gate.record_finding(request_id="f-1", actor_id="r1", finding_id="f1",
                                 batch_id="b-vulnerability", severity="critical",
                                 title="提示词注入可越权")
        return version

    def test_open_critical_finding_blocks(self):
        self.prepare()
        evaluation = self.gate.explain_gate("c1")
        self.assertFalse(evaluation.satisfied)
        self.assertEqual("finding_open", evaluation.blocking_reasons[0].code)
        self.assertEqual("f1", evaluation.blocking_reasons[0].refs["finding_id"])
        decision = self.decision()
        self.assertEqual(DECISION_REJECTED, decision["state"])

    def test_evidence_on_other_version_does_not_unblock(self):
        version = self.prepare()
        self.gate.add_evidence(request_id="e-old", actor_id="op1", evidence_id="e-old",
                               finding_id="f1", kind="patch", reference="PR-9",
                               version_pin="2026.09.01")
        evaluation = self.gate.explain_gate("c1")
        codes = {r.code for r in evaluation.blocking_reasons}
        self.assertEqual({"evidence_version_mismatch"}, codes)
        reason = evaluation.blocking_reasons[0]
        self.assertEqual([{"evidence_id": "e-old", "version_pin": "2026.09.01"}],
                         reason.refs["evidence_on_other_versions"])
        self.assertIn(version, reason.recovery)
        self.gate.add_evidence(request_id="e-new", actor_id="op1", evidence_id="e-new",
                               finding_id="f1", kind="retest", reference="RET-12",
                               version_pin=version)
        self.assertTrue(self.gate.explain_gate("c1").satisfied)

    def test_same_version_evidence_allows_release(self):
        version = self.prepare()
        self.gate.add_evidence(request_id="e1", actor_id="op1", evidence_id="e1",
                               finding_id="f1", kind="retest", reference="复测报告-1",
                               version_pin=version)
        decision = self.decision()
        self.assertEqual(DECISION_APPROVED, decision["state"])

    def test_low_severity_does_not_block(self):
        self.create_candidate()
        self.complete_all_checks()
        self.gate.record_finding(request_id="f-low", actor_id="r1", finding_id="flow",
                                 batch_id="b-permission", severity="low", title="日志措辞")
        self.assertTrue(self.gate.explain_gate("c1").satisfied)


class ExceptionGateTest(GateTestBase):
    def setUp(self):
        super().setUp()
        self.version = self.create_candidate()
        self.complete_all_checks(version=self.version)
        self.gate.record_finding(request_id="f-1", actor_id="r1", finding_id="f1",
                                 batch_id="b-data_leak", severity="high",
                                 title="训练样本含个人信息")
        self.expires = (self.clock.now() + timedelta(days=7)).isoformat().replace("+00:00", "Z")

    def test_active_exception_allows_release(self):
        self.gate.approve_exception(request_id="ex-1", actor_id="a1", exception_id="x1",
                                    finding_id="f1", reason="发布委员会承担残余风险",
                                    expires_at=self.expires)
        evaluation = self.gate.explain_gate("c1")
        self.assertTrue(evaluation.satisfied)
        self.assertEqual("x1", evaluation.exceptions[0]["exception_id"])
        decision = self.decision()
        self.assertEqual(DECISION_APPROVED, decision["state"])

    def test_expired_exception_blocks_and_invalidates_old_approval(self):
        # 在例外有效期内取得批准。
        self.gate.approve_exception(request_id="ex-1", actor_id="a1", exception_id="x1",
                                    finding_id="f1", reason="临时放行",
                                    expires_at=self.expires)
        approved = self.decision(request_id="dec-ok")
        self.assertEqual(DECISION_APPROVED, approved["state"])
        # 时钟越过到期时刻后，旧批准必须失效。
        self.gate.clock = self.make_clock(2026, 10, 10)
        status = self.gate.current_status("c1")
        self.assertFalse(status["evaluation"]["satisfied"])
        codes = {r["code"] for r in status["evaluation"]["blocking_reasons"]}
        self.assertEqual({"finding_open"}, codes)
        self.assertEqual("exception_expired",
                         status["last_invalidated_decision"]["invalidated_reason"])
        history = self.gate.list_decisions("c1")
        self.assertEqual(DECISION_INVALIDATED, history[0]["state"])
        self.assertIsNone(status["live_decision"])

    def test_revoked_exception_invalidates_approval(self):
        self.gate.approve_exception(request_id="ex-1", actor_id="a1", exception_id="x1",
                                    finding_id="f1", reason="临时放行",
                                    expires_at=self.expires)
        self.decision(request_id="dec-ok")
        self.gate.revoke_exception(request_id="rev-1", actor_id="a1", exception_id="x1")
        status = self.gate.current_status("c1")
        self.assertFalse(status["evaluation"]["satisfied"])
        self.assertEqual("exception_revoked",
                         status["last_invalidated_decision"]["invalidated_reason"])
        decision = self.decision(request_id="dec-after")
        self.assertEqual(DECISION_REJECTED, decision["state"])
        self.assertEqual(DECISION_INVALIDATED,
                         self.gate.list_decisions("c1")[0]["state"])

    def test_reviewer_cannot_approve_exception(self):
        with self.assertRaises(PermissionDenied):
            self.gate.approve_exception(request_id="ex-x", actor_id="r1", exception_id="xx",
                                        finding_id="f1", reason="x", expires_at=self.expires)


class ReopenGateTest(GateTestBase):
    def setUp(self):
        super().setUp()
        self.version = self.create_candidate()
        self.complete_all_checks(version=self.version)
        self.gate.record_finding(request_id="f-1", actor_id="r1", finding_id="f1",
                                 batch_id="b-vulnerability", severity="critical",
                                 title="越权漏洞")
        self.gate.add_evidence(request_id="e1", actor_id="op1", evidence_id="e1",
                               finding_id="f1", kind="retest", reference="复测-1",
                               version_pin=self.version)
        self.approved = self.decision(request_id="dec-1")

    def test_reopen_invalidates_approval_without_overwriting_history(self):
        self.gate.reopen_finding(request_id="ro-1", actor_id="r1", finding_id="f1",
                                 reason="复测复现越权")
        history = self.gate.list_decisions("c1")
        self.assertEqual(1, len(history))
        self.assertEqual(DECISION_INVALIDATED, history[0]["state"])
        self.assertEqual("finding_reopened", history[0]["invalidated_reason"])
        # 历史行内容保留：结果仍是 approved，只是状态标记为 invalidated。
        self.assertEqual(DECISION_APPROVED, history[0]["result"])
        status = self.gate.current_status("c1")
        self.assertFalse(status["evaluation"]["satisfied"])
        self.assertEqual("finding_reopened",
                         status["evaluation"]["blocking_reasons"][0]["code"])

    def test_new_decision_after_reopen_is_rejected_then_reresolve_approves(self):
        self.gate.reopen_finding(request_id="ro-1", actor_id="r1", finding_id="f1",
                                 reason="复现")
        rejected = self.decision(request_id="dec-2")
        self.assertEqual(DECISION_REJECTED, rejected["state"])
        # 在同一候选版本上重新修复并复测后恢复。
        self.gate.add_evidence(request_id="e2", actor_id="op1", evidence_id="e2",
                               finding_id="f1", kind="retest", reference="复测-2",
                               version_pin=self.version)
        approved_again = self.decision(request_id="dec-3")
        self.assertEqual(DECISION_APPROVED, approved_again["state"])
        history = self.gate.list_decisions("c1")
        states = [d["state"] for d in history]
        self.assertEqual([DECISION_INVALIDATED, DECISION_SUPERSEDED, DECISION_APPROVED],
                         states)
        # 中间的拒绝决定指向它取代的旧批准，链条完整。
        self.assertEqual(history[0]["decision_id"], history[1]["supersedes_decision_id"])

    def test_reopen_nonblocking_finding_does_not_invalidate(self):
        self.gate.record_finding(request_id="f-low", actor_id="r1", finding_id="flow",
                                 batch_id="b-permission", severity="low", title="小问题")
        self.gate.reopen_finding(request_id="ro-low", actor_id="r1", finding_id="flow",
                                 reason="再看看")
        self.assertEqual(DECISION_APPROVED,
                         self.gate.list_decisions("c1")[0]["state"])

    def test_new_exception_after_reopen_can_restore_release(self):
        from ai_governance_foundation.clock import FixedClock

        def advance(minutes):
            value = self.clock.now() + timedelta(minutes=minutes)
            new_clock = FixedClock(value)
            self.clock = new_clock
            self.gate.clock = new_clock
            self.service.clock = new_clock

        expires = (self.clock.now() + timedelta(days=30)).isoformat().replace("+00:00", "Z")
        # 重新打开之前就存在的旧例外。
        self.gate.approve_exception(request_id="ex-old", actor_id="a1", exception_id="xold",
                                    finding_id="f1", reason="旧例外", expires_at=expires)
        advance(10)
        self.gate.reopen_finding(request_id="ro-1", actor_id="r1", finding_id="f1",
                                 reason="复现")
        evaluation = self.gate.explain_gate("c1")
        self.assertFalse(evaluation.satisfied)
        self.assertEqual("finding_reopened", evaluation.blocking_reasons[0].code)
        # 就重新打开的事实重新复评后批准的新例外可以恢复发布。
        advance(10)
        new_expires = (self.clock.now() + timedelta(days=30)).isoformat().replace("+00:00", "Z")
        self.gate.approve_exception(request_id="ex-new", actor_id="a1", exception_id="xnew",
                                    finding_id="f1",
                                    reason="已就重新打开的事实复评，委员会承担风险",
                                    expires_at=new_expires)
        decision = self.decision(request_id="dec-again")
        self.assertEqual(DECISION_APPROVED, decision["state"])

    def test_only_reviewer_or_admin_can_reopen(self):
        with self.assertRaises(PermissionDenied):
            self.gate.reopen_finding(request_id="ro-x", actor_id="op1", finding_id="f1",
                                     reason="x")
        with self.assertRaises(PermissionDenied):
            self.gate.reopen_finding(request_id="ro-y", actor_id="au1", finding_id="f1",
                                     reason="x")


class InvalidationTriggerTest(GateTestBase):
    def setUp(self):
        super().setUp()
        self.version = self.create_candidate()
        self.complete_all_checks(version=self.version)
        self.approved = self.decision(request_id="dec-1")

    def test_new_evaluation_round_invalidates_approval(self):
        self.gate.register_batch(request_id="batch-new", actor_id="r1",
                                 batch_id="b-vuln-2", candidate_id="c1",
                                 check_family="vulnerability", version_pin=self.version)
        status = self.gate.current_status("c1")
        self.assertEqual("evaluation_superseded",
                         status["last_invalidated_decision"]["invalidated_reason"])
        reason_codes = {r["code"] for r in status["evaluation"]["blocking_reasons"]}
        self.assertEqual({"check_incomplete"}, reason_codes)

    def test_new_critical_finding_invalidates_approval(self):
        self.gate.record_finding(request_id="f-new", actor_id="r1", finding_id="f9",
                                 batch_id="b-vulnerability", severity="high",
                                 title="新的权限提升")
        status = self.gate.current_status("c1")
        self.assertEqual("new_blocking_finding",
                         status["last_invalidated_decision"]["invalidated_reason"])
        reason_codes = {r["code"] for r in status["evaluation"]["blocking_reasons"]}
        self.assertEqual({"finding_open"}, reason_codes)


class DecisionConsistencyTest(GateTestBase):
    def test_unchanged_state_reuses_live_decision(self):
        self.create_candidate()
        self.complete_all_checks()
        first = self.gate.generate_decision(request_id="dec-1", actor_id="a1",
                                            candidate_id="c1")
        second = self.gate.generate_decision(request_id="dec-2", actor_id="a1",
                                             candidate_id="c1")
        self.assertEqual(first.resource_id, second.resource_id)
        self.assertFalse(second.replayed)
        self.assertEqual(1, len(self.gate.list_decisions("c1")))

    def test_idempotent_replay_returns_same_decision(self):
        self.create_candidate()
        self.complete_all_checks()
        first = self.gate.generate_decision(request_id="dec-same", actor_id="a1",
                                            candidate_id="c1", rationale="放行")
        second = self.gate.generate_decision(request_id="dec-same", actor_id="a1",
                                             candidate_id="c1", rationale="放行")
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)

    def test_concurrent_decisions_never_produce_two_live(self):
        self.create_candidate()
        self.complete_all_checks()
        results: list[str] = []
        errors: list[Exception] = []
        barrier = threading.Barrier(8)

        def worker(index):
            try:
                barrier.wait()
                receipt = self.gate.generate_decision(
                    request_id=f"dec-concurrent-{index}", actor_id="a1", candidate_id="c1")
                results.append(receipt.resource_id)
            except Exception as exc:  # pragma: no cover - 失败时记录
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)
        self.assertEqual(1, len(set(results)))
        rows = self.database.connection.execute(
            "SELECT COUNT(*) AS c FROM release_decisions"
        ).fetchone()["c"]
        self.assertEqual(1, rows)
        live = self.database.connection.execute(
            "SELECT COUNT(*) AS c FROM release_decisions "
            "WHERE superseded_by_decision_id IS NULL AND invalidated_at IS NULL"
        ).fetchone()["c"]
        self.assertEqual(1, live)

    def test_concurrent_reopen_and_decide_leave_no_approved_live(self):
        version = self.create_candidate()
        self.complete_all_checks(version=version)
        self.gate.record_finding(request_id="f-1", actor_id="r1", finding_id="f1",
                                 batch_id="b-vulnerability", severity="critical",
                                 title="漏洞")
        self.gate.add_evidence(request_id="e1", actor_id="op1", evidence_id="e1",
                               finding_id="f1", kind="retest", reference="r",
                               version_pin=version)
        self.decision(request_id="dec-approved")

        barrier = threading.Barrier(2)

        def reopen():
            barrier.wait()
            self.gate.reopen_finding(request_id="ro-concurrent", actor_id="r1",
                                     finding_id="f1", reason="并发复现")

        def decide():
            barrier.wait()
            self.gate.generate_decision(request_id="dec-concurrent", actor_id="a1",
                                        candidate_id="c1")

        threads = [threading.Thread(target=reopen), threading.Thread(target=decide)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        live_rows = self.database.connection.execute(
            "SELECT result FROM release_decisions "
            "WHERE superseded_by_decision_id IS NULL AND invalidated_at IS NULL"
        ).fetchall()
        self.assertNotIn("approved", [row["result"] for row in live_rows])
        self.assertLessEqual(len(live_rows), 1)

    def test_state_persists_across_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.sqlite3"
            database = Database(path)
            gate = GateService(database, self.make_clock(2026, 10, 1, 8))
            bootstrap = DomainService(database, self.make_clock(2026, 10, 1, 8))
            bootstrap.register_organization(request_id="org", actor_id="bootstrap",
                                            organization_id="o1", name="治理机构")
            bootstrap.register_actor(request_id="admin", actor_id="bootstrap",
                                     new_actor_id="a1", display_name="管理员",
                                     role="admin", organization_id="o1")
            bootstrap.register_actor(request_id="reviewer", actor_id="a1",
                                     new_actor_id="r1", display_name="评审",
                                     role="reviewer", organization_id="o1")
            gate.register_candidate(request_id="c1", actor_id="a1", candidate_id="c1",
                                    model_id="model-x", version="v1")
            for family in FAMILIES:
                gate.register_batch(request_id=f"b-{family}", actor_id="r1",
                                    batch_id=f"b-{family}", candidate_id="c1",
                                    check_family=family, version_pin="v1")
                gate.complete_batch(request_id=f"d-{family}", actor_id="r1",
                                    batch_id=f"b-{family}")
            receipt = gate.generate_decision(request_id="dec-1", actor_id="a1",
                                             candidate_id="c1")
            decision_id = receipt.resource_id
            valid, _ = bootstrap.verify_audit()
            self.assertTrue(valid)
            database.close()

            database2 = Database(path)
            gate2 = GateService(database2, self.make_clock(2026, 10, 1, 8))
            decision = gate2.get_decision(decision_id)
            self.assertEqual(DECISION_APPROVED, decision["state"])
            self.assertTrue(gate2.explain_gate("c1").satisfied)
            database2.close()


class GateApiTest(GateTestBase):
    def test_status_endpoint_explains_block(self):
        from ai_governance_foundation.api import route

        self.create_candidate()
        self.add_completed_batch("vulnerability")
        status, payload = route(self.service, "GET", "/gate-status?candidate_id=c1", None,
                                {"X-Actor-Id": "au1"}, gate_service=self.gate)
        self.assertEqual(200, status)
        self.assertFalse(payload["evaluation"]["satisfied"])
        codes = {r["code"] for r in payload["evaluation"]["blocking_reasons"]}
        self.assertEqual({"check_missing"}, codes)
        for reason in payload["evaluation"]["blocking_reasons"]:
            self.assertIn("recovery", reason)

    def test_decision_endpoint_and_permission(self):
        from ai_governance_foundation.api import route

        self.create_candidate()
        self.complete_all_checks()
        status, payload = route(self.service, "POST", "/release-decisions",
                                {"request_id": "dec-x", "candidate_id": "c1"},
                                {"X-Actor-Id": "r1"}, gate_service=self.gate)
        self.assertEqual(403, status)
        status, payload = route(self.service, "POST", "/release-decisions",
                                {"request_id": "dec-x", "candidate_id": "c1"},
                                {"X-Actor-Id": "a1"}, gate_service=self.gate)
        self.assertEqual(201, status)
        decision_id = payload["resource_id"]
        status, payload = route(
            self.service, "GET", f"/release-decisions?decision_id={decision_id}", None,
            {"X-Actor-Id": "au1"}, gate_service=self.gate)
        self.assertEqual(200, status)
        self.assertEqual(DECISION_APPROVED, payload["state"])


class GateAcceptanceModuleTest(unittest.TestCase):
    def test_gate_acceptance_run(self):
        from ai_governance_foundation.gate_acceptance import run

        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])


class GateHttpConcurrencyTest(GateTestBase):
    """通过真实 ThreadingHTTPServer 验证并发提交不会产生矛盾决定。"""

    def test_concurrent_decisions_over_http(self):
        Handler.service = self.service
        Handler.gate_service = self.gate
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.create_candidate()
            self.complete_all_checks()

            def post(index):
                payload = json.dumps({"request_id": f"http-dec-{index}",
                                      "candidate_id": "c1"}).encode("utf-8")
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/release-decisions", data=payload,
                    headers={"Content-Type": "application/json", "X-Actor-Id": "a1"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status, json.loads(response.read())

            with self.subTest(threads=12):
                results = []
                threads = []
                for i in range(12):
                    worker = threading.Thread(
                        target=lambda i=i: results.append(post(i)))
                    threads.append(worker)
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            decision_ids = {body["resource_id"] for _, body in results}
            self.assertEqual(1, len(decision_ids))
            statuses = {status for status, _ in results}
            self.assertEqual({201}, statuses)

            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/gate-status?candidate_id=c1", timeout=10
            ) as response:
                body = json.loads(response.read())
            self.assertEqual("approved", body["live_decision"]["state"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
