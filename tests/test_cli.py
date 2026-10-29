from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-B", "-m", "engine.cli", *map(str, args)], cwd=ROOT, capture_output=True, encoding="utf-8")

    def test_full_cli_copy_workflow_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = ROOT / "demo/cases/04_auto_repairable"
            commands = [
                ("audit", source, "-o", out / "audit.json"),
                ("plan", source, "-o", out / "plan.json"),
                ("repair", source, "--plan", out / "plan.json", "--confirm", "-o", out / "repair"),
                ("report", out / "audit.json", "--repair-report", out / "repair/repair_report.json", "-o", out / "report.html"),
            ]
            for command in commands:
                result = self.run_cli(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
            report = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("unreviewed", report)
            self.assertIn("TST004", report)

    def test_fail_on_exit_codes_and_legacy_audit(self):
        self.assertEqual(self.run_cli("audit", ROOT / "tests/fixtures/review_skill", "--fail-on", "high").returncode, 1)
        self.assertEqual(self.run_cli(ROOT / "tests/fixtures/safe_skill").returncode, 0)
        self.assertEqual(self.run_cli("audit", ROOT / "missing-file").returncode, 2)

    def test_outputs_cannot_overwrite_input_or_existing_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SKILL.md"
            source.write_text("# safe", encoding="utf-8")
            self.assertEqual(self.run_cli("audit", source, "-o", source).returncode, 2)
            self.assertEqual(source.read_text(), "# safe")
            output = Path(tmp) / "keep.json"
            output.write_text("keep", encoding="utf-8")
            self.assertEqual(self.run_cli("audit", source, "-o", output).returncode, 2)
            self.assertEqual(output.read_text(), "keep")

    def test_repair_without_confirmation_or_plan_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = ROOT / "demo/cases/04_auto_repairable"
            self.assertEqual(self.run_cli("plan", source, "-o", out / "plan.json").returncode, 0)
            self.assertEqual(self.run_cli("repair", source, "--plan", out / "plan.json", "-o", out / "repair").returncode, 2)
            self.assertEqual(self.run_cli("repair", source, "--confirm", "-o", out / "repair").returncode, 2)
            self.assertFalse((out / "repair").exists())

    def test_review_template_is_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            source = ROOT / "demo/cases/04_auto_repairable"
            self.assertEqual(self.run_cli("audit", source, "-o", out / "audit.json").returncode, 0)
            self.assertEqual(self.run_cli("review-template", out / "audit.json", "-o", out / "review.json").returncode, 0)
            self.assertEqual(self.run_cli("review", out / "audit.json", "--review", out / "review.json", "-o", out / "reviewed.json").returncode, 2)
            self.assertFalse((out / "reviewed.json").exists())


if __name__ == "__main__":
    unittest.main()
