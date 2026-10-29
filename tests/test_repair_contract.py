from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.repair import RepairError, apply_patch_plan, build_patch_plan
from engine.scanner import audit

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "demo/cases/04_auto_repairable"


class RepairContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        shutil.copytree(FIXTURE, self.source)
        self.plan = build_patch_plan(self.source)
        self.output = self.root / "result"

    def test_confirm_without_approved_plan_is_rejected(self):
        with self.assertRaises(RepairError):
            apply_patch_plan(self.source, self.output, confirmed=True)
        self.assertFalse(self.output.exists())

    def test_changed_source_requires_new_approval(self):
        (self.source / "new.txt").write_text("changed", encoding="utf-8")
        with self.assertRaises(RepairError):
            apply_patch_plan(self.source, self.output, confirmed=True, patch_plan=self.plan)
        self.assertFalse(self.output.exists())

    def test_tampered_plan_is_rejected(self):
        changed = copy.deepcopy(self.plan)
        changed["operations"][0]["target"] = "SKILL.md"
        with self.assertRaises(RepairError):
            apply_patch_plan(self.source, self.output, confirmed=True, patch_plan=changed)
        self.assertFalse(self.output.exists())

    def test_source_changes_during_copy_abort_delivery(self):
        original = shutil.copytree
        def changed_copy(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            (self.source / "changed.txt").write_text("changed after copy", encoding="utf-8")
            return result
        with patch("engine.repair.shutil.copytree", side_effect=changed_copy):
            with self.assertRaises(RepairError):
                apply_patch_plan(self.source, self.output, confirmed=True, patch_plan=self.plan)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".skillsentinel-*")))

    def test_existing_output_and_nested_output_are_rejected(self):
        self.output.mkdir()
        (self.output / "keep.txt").write_text("keep", encoding="utf-8")
        for output in (self.output, self.source / "out"):
            with self.subTest(output=output), self.assertRaises(RepairError):
                apply_patch_plan(self.source, output, confirmed=True, patch_plan=self.plan)
        self.assertEqual((self.output / "keep.txt").read_text(), "keep")

    def test_draft_tests_and_risk_retention_are_explicit(self):
        report = apply_patch_plan(self.source, self.output, confirmed=True, patch_plan=self.plan)
        cases = json.loads((self.output / "patched_skill/tests/cases.json").read_text(encoding="utf-8"))
        self.assertTrue(cases["requires_manual_validation"])
        self.assertIn("TST004", report["remaining_findings"])
        self.assertEqual(report["runtime_risks_removed"], 0)
        self.assertEqual(report["resolved_quality_findings"], ["HITL001", "RES001", "TST001"])
        self.assertTrue(report["source_unchanged"])
        self.assertEqual(report["source_sha256"], self.plan["source_sha256"])
        self.assertEqual(audit(self.source)["input"]["sha256"], self.plan["source_sha256"])

    def test_nested_skill_places_tests_next_to_entry(self):
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        shutil.move(self.source, wrapper / "nested")
        plan = build_patch_plan(wrapper)
        report = apply_patch_plan(wrapper, self.output, confirmed=True, patch_plan=plan)
        self.assertTrue((self.output / "patched_skill/nested/tests/cases.json").exists())
        self.assertFalse((self.output / "patched_skill/tests").exists())
        self.assertNotIn("TST001", report["remaining_findings"])

    def test_binary_asset_is_preserved_and_coverage_remains_partial(self):
        asset = self.source / "asset.png"
        asset.write_bytes(b"\x89PNG\x00inert")
        plan = build_patch_plan(self.source)
        apply_patch_plan(self.source, self.output, confirmed=True, patch_plan=plan)
        self.assertEqual((self.output / "patched_skill/asset.png").read_bytes(), asset.read_bytes())
        after = json.loads((self.output / "after_audit.json").read_text(encoding="utf-8"))
        self.assertFalse(after["coverage"]["complete"])

    def test_bom_and_newlines_are_preserved(self):
        entry = self.source / "SKILL.md"
        original = entry.read_bytes().decode("utf-8")
        for index, (bom, newline) in enumerate(((b"", "\n"), (b"\xef\xbb\xbf", "\r\n"), (b"", "\r"))):
            with self.subTest(newline=repr(newline), bom=bool(bom)):
                raw = bom + original.replace("\n", newline).encode("utf-8")
                entry.write_bytes(raw)
                plan = build_patch_plan(self.source)
                output = self.root / f"format-{index}"
                apply_patch_plan(self.source, output, confirmed=True, patch_plan=plan)
                patched = (output / "patched_skill/SKILL.md").read_bytes()
                self.assertTrue(patched.startswith(raw))
                self.assertEqual(entry.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
