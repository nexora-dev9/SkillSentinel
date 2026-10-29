from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.repair import apply_patch_plan, build_patch_plan
from engine.scanner import audit


ROOT = Path(__file__).resolve().parents[1]
MATRIX = json.loads((ROOT / "demo" / "VALIDATION_MATRIX.json").read_text(encoding="utf-8"))


class SkillSentinelDemoSuiteTests(unittest.TestCase):
    def test_validation_matrix_matches_deterministic_engine(self) -> None:
        for case in MATRIX["cases"]:
            with self.subTest(case=case["id"]):
                source = ROOT / case["source"]
                result = audit(source)
                ids = {item["id"] for item in result["findings"]}
                self.assertTrue(set(case["expected_ids"]) <= ids, (case["id"], sorted(ids)))

                plan = build_patch_plan(source)
                has_operations = bool(plan.get("operations"))
                self.assertEqual(has_operations, case["repair_expected"], (case["id"], plan))

    def test_safe_demo_has_no_findings(self) -> None:
        result = audit(ROOT / "demo" / "cases" / "01_safe_local_summary")
        self.assertEqual(result["summary"]["findings"], 0)

    def test_auto_repair_demo_resolves_only_deterministic_items(self) -> None:
        source = ROOT / "demo" / "cases" / "04_auto_repairable"
        before = audit(source)
        before_ids = [item["id"] for item in before["findings"]]
        self.assertTrue({"TST001", "HITL001", "RES001"} <= set(before_ids))

        with tempfile.TemporaryDirectory() as tmp:
            report = apply_patch_plan(source, Path(tmp) / "repair", confirmed=True, patch_plan=build_patch_plan(source))
            after = audit(Path(tmp) / "repair" / "patched_skill")
            after_ids = [item["id"] for item in after["findings"]]

            self.assertNotIn("TST001", after_ids)
            self.assertNotIn("HITL001", after_ids)
            self.assertNotIn("RES001", after_ids)
            self.assertIn("OUT001", after_ids)
            self.assertIn("NET001", after_ids)
            self.assertIn("SEM001", after_ids)
            self.assertEqual(report["after"], after["summary"])


if __name__ == "__main__":
    unittest.main()
