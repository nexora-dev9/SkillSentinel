from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from engine.repair import RepairConfirmationRequired, apply_patch_plan, build_patch_plan
from engine.scanner import audit


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "review_skill"


class SkillSentinelRepairTests(unittest.TestCase):
    def test_plan_is_read_only_and_only_contains_supported_fixes(self) -> None:
        original = (SOURCE / "SKILL.md").read_text(encoding="utf-8")
        plan = build_patch_plan(SOURCE)
        kinds = {operation["kind"] for operation in plan["operations"]}
        self.assertEqual(kinds, {"create_cases", "append_safety_guardrails"})
        self.assertIn("SEC001", plan["non_auto_fix_findings"])
        self.assertEqual((SOURCE / "SKILL.md").read_text(encoding="utf-8"), original)
        self.assertFalse((SOURCE / "tests" / "cases.json").exists())

    def test_apply_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RepairConfirmationRequired):
                apply_patch_plan(SOURCE, Path(tmp) / "run", confirmed=False)

    def test_apply_repairs_copy_then_rescans_without_touching_source(self) -> None:
        original = (SOURCE / "SKILL.md").read_text(encoding="utf-8")
        original_bytes = (SOURCE / "SKILL.md").read_bytes()
        before = audit(SOURCE)
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "repair-run"
            report = apply_patch_plan(SOURCE, run_dir, confirmed=True, patch_plan=build_patch_plan(SOURCE))
            patched = run_dir / "patched_skill"

            self.assertTrue((patched / "tests" / "cases.json").exists())
            self.assertTrue((run_dir / "repair.diff").exists())
            self.assertTrue((run_dir / "repair_report.json").exists())
            self.assertTrue((run_dir / "patched_skill.zip").exists())

            patched_text = (patched / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("SkillSentinel Safety Guardrails", patched_text)
            patched_bytes = (patched / "SKILL.md").read_bytes()
            original_body = original_bytes.rstrip(b"\r\n")
            self.assertEqual(patched_bytes[: len(original_body)], original_body)
            if b"\r\n" not in original_bytes:
                self.assertNotIn(b"\r\n", patched_bytes)
            self.assertEqual((SOURCE / "SKILL.md").read_text(encoding="utf-8"), original)
            self.assertFalse((SOURCE / "tests" / "cases.json").exists())

            after = audit(patched)
            after_ids = {item["id"] for item in after["findings"]}
            self.assertNotIn("TST001", after_ids)
            self.assertNotIn("HITL001", after_ids)
            self.assertNotIn("RES001", after_ids)
            self.assertIn("SEC001", after_ids)
            self.assertLess(after["summary"]["findings"], before["summary"]["findings"])
            self.assertEqual(report["after"], after["summary"])


if __name__ == "__main__":
    unittest.main()
