"""Frozen chronological boundaries and preserved-snapshot contracts."""

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from src.finalize_dataset import split_name, split_rows, validate_split_config, verify_snapshots


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(Path("config/experiment.json").read_text())

    def row(self, sid, day):
        actual = (date(2026, 10, 26) + timedelta(days=day - 1)).isoformat()
        return {"SessionID": sid, "SimulationDay": str(day), "ScenarioID": "N01",
                "GroundTruthLabel": "0", "ActualExecutionUTC": actual + "T10:00:00Z",
                "ObservationStartUTC": actual + "T10:00:00Z", "PredictionCutoffUTC": actual + "T10:01:00Z",
                "FeatureOriginal14DayCohortEligible": "true", "FeatureMLTrainingEligible": "true",
                "MLTrainingEligible": "true", "ClockPolicyStatus": "no_large_disagreement_observed",
                "AmbiguousArchiveCandidates": "0", "PriorOverlapExclusion": "false", "LateRecovery": "false"}

    def test_exact_frozen_boundaries(self):
        validate_split_config(self.config)
        for day, expected in [(1, "train"), (8, "train"), (9, "validation"),
                              (10, "validation"), (11, "test"), (14, "test")]:
            self.assertEqual(split_name(day, self.config), expected)
        bad = copy.deepcopy(self.config)
        bad["validation_days"] = [10, 10]
        with self.assertRaises(ValueError):
            validate_split_config(bad)

    def test_late_recovery_retained_and_cross_boundary_row_not_moved(self):
        rows = [self.row("a", 1), self.row("b", 9), self.row("c", 11),
                self.row("crossing", 8), self.row("recovered", 14)]
        rows[3]["PredictionCutoffUTC"] = "2026-11-03T00:01:00Z"
        rows[4].update(LateRecovery="true", FeatureOriginal14DayCohortEligible="false",
                       ActualExecutionUTC="2026-11-09T10:00:00Z")
        original = copy.deepcopy(rows)
        manifest, groups = split_rows(rows, self.config)
        self.assertEqual(len(manifest), 5)
        self.assertEqual(manifest[3]["Partition"], "train")
        self.assertEqual(manifest[3]["Included"], "false")
        self.assertIn("observation_crosses_partition_boundary", manifest[3]["ExclusionReasons"])
        self.assertEqual(manifest[4]["Included"], "false")
        self.assertIn("late_recovery_extended_only", manifest[4]["ExclusionReasons"])
        self.assertEqual(rows, original)
        self.assertEqual([len(groups[k]) for k in ["train", "validation", "test"]], [1, 1, 1])

    def test_snapshot_verification_never_repairs_or_rewrites_tampered_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            lines = []
            for name in ["session_features.csv", "ml_dataset.csv"]:
                (folder / name).write_bytes(b"synthetic\n")
                lines.append(hashlib.sha256(b"synthetic\n").hexdigest() + "  " + name)
            checksums = folder / "SHA256SUMS.txt"
            checksums.write_text("\n".join(lines) + "\n")
            before = checksums.read_bytes()
            verify_snapshots(folder)
            (folder / "ml_dataset.csv").write_bytes(b"tampered\n")
            with self.assertRaises(ValueError):
                verify_snapshots(folder)
            self.assertEqual(checksums.read_bytes(), before)
            self.assertEqual((folder / "ml_dataset.csv").read_bytes(), b"tampered\n")


if __name__ == "__main__":
    unittest.main()
