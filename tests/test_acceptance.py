import unittest

from ai_governance_foundation.acceptance import run


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["first_replayed"])
        self.assertTrue(result["second_replayed"])
        self.assertEqual(1, result["records"])
        gate = result["gate"]
        self.assertEqual("blocked", gate["first_decision"])
        self.assertEqual(["finding_unresolved"], gate["first_blockers"])
        self.assertEqual("approved", gate["second_decision"])
        self.assertTrue(gate["reopen_invalidated"])
        self.assertFalse(gate["current_valid_after_reopen"])
        self.assertEqual("approved", gate["final_decision"])
        self.assertTrue(gate["current_valid_final"])


if __name__ == "__main__":
    unittest.main()
