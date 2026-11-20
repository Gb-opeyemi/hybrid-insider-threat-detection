"""Run from the repository root: python -m unittest tests.test_hybrid_priority"""

import unittest

from src.hybrid_priority import fuse_hybrid_priority


class HybridPriorityTests(unittest.TestCase):
    def test_both_detected_high(self):
        d = fuse_hybrid_priority(1, 1, wazuh_evidence_verified=True)
        self.assertEqual((d.hybrid_priority, d.high_priority_alert, d.review_required),
                         ("High Priority", 1, 1))

    def test_disagreement_needs_review(self):
        for rf, wazuh in ((0, 1), (1, 0)):
            with self.subTest(rf=rf, wazuh=wazuh):
                d = fuse_hybrid_priority(rf, wazuh, wazuh_evidence_verified=True)
                self.assertEqual((d.hybrid_priority, d.high_priority_alert, d.review_required),
                                 ("Needs Review", 0, 1))

    def test_neither_detected_low(self):
        d = fuse_hybrid_priority(0, 0, wazuh_evidence_verified=True)
        self.assertEqual((d.hybrid_priority, d.high_priority_alert, d.review_required),
                         ("Low Risk", 0, 0))

    def test_missing_rule_evidence_fails_safe(self):
        d = fuse_hybrid_priority(0, None, wazuh_evidence_verified=False)
        self.assertEqual((d.hybrid_priority, d.high_priority_alert, d.review_required),
                         ("Evidence Unavailable", 0, 1))
        self.assertIsNone(d.wazuh_detected)

    def test_verified_requires_decision(self):
        with self.assertRaises(ValueError):
            fuse_hybrid_priority(1, None, wazuh_evidence_verified=True)

    def test_unverified_must_not_assume_negative(self):
        with self.assertRaises(ValueError):
            fuse_hybrid_priority(0, 0, wazuh_evidence_verified=False)

    def test_rejects_string_flags(self):
        with self.assertRaises(ValueError):
            fuse_hybrid_priority("0", 1, wazuh_evidence_verified=True)

    def test_matches_offline_cell_e_counts(self):
        # Known held-out test prediction pairing (counts only), not ground truth.
        pairs = [(1, 1)] * 68 + [(0, 1)] * 27 + [(0, 0)] * 191
        results = [fuse_hybrid_priority(r, w, wazuh_evidence_verified=True)
                   for r, w in pairs]
        self.assertEqual(sum(d.high_priority_alert for d in results), 68)
        self.assertEqual(sum(d.review_required for d in results), 95)
        self.assertEqual(sum(d.hybrid_priority == "Low Risk" for d in results), 191)


if __name__ == "__main__":
    unittest.main()
