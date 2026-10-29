from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from skill.build_skill import build
from tools.evaluate_pairs import evaluate

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_skill_zip_runs_in_isolation_with_matching_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, archive_path = build(root / "build")
            manifest = json.loads((root / "build/manifest.json").read_text())
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    self.assertNotIn("__pycache__", info.filename)
                    self.assertEqual(hashlib.sha256(archive.read(info)).hexdigest(), manifest[info.filename])
                archive.extractall(root / "unpacked")
            runner = root / "unpacked/skillsentinel/scripts/run_skillsentinel.py"
            result = subprocess.run([sys.executable, "-I", "-B", str(runner), "audit", str(ROOT / "tests/fixtures/safe_skill")], cwd=root, capture_output=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["summary"]["findings"], 0)
            first = archive_path.read_bytes()
            build(root / "build")
            self.assertEqual(archive_path.read_bytes(), first)

    def test_build_cannot_replace_source_directory(self):
        with self.assertRaises(ValueError):
            build(ROOT)

    def test_paired_static_validation_does_not_invent_model_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = evaluate(Path(tmp) / "evaluation")
            self.assertEqual(result["static_passed"], result["total"])
            self.assertEqual(result["total"], 12)
            self.assertEqual(result["semantic_reviewed"], 0)
            self.assertIsNone(result["semantic_accuracy"])


if __name__ == "__main__":
    unittest.main()
