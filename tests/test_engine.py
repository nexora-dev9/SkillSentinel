from __future__ import annotations

import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from engine.safe_reader import UnsafeInputError, load_input
from engine.scanner import audit


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class SkillSentinelEngineTests(unittest.TestCase):
    def test_safe_directory_is_supported(self) -> None:
        result = audit(FIXTURES / "safe_skill")
        self.assertEqual(result["input"]["type"], "skill_directory")
        self.assertEqual(result["summary"]["findings"], 0)

    def test_review_fixture_produces_evidence_and_semantic_review(self) -> None:
        result = audit(FIXTURES / "review_skill")
        ids = {finding["id"] for finding in result["findings"]}
        self.assertTrue({"SEC001", "CAP001", "NET001", "OUT001", "TST001", "SEM001"} <= ids)
        self.assertTrue(result["summary"]["requires_semantic_review"])
        secret = next(item for item in result["findings"] if item["id"] == "SEC001")
        self.assertIn("<REDACTED>", secret["evidence"][0]["snippet"])
        self.assertIn("DEMO_API_KEY", secret["evidence"][0]["snippet"])
        self.assertNotIn("TEST_FAKE_TOKEN_12345", secret["evidence"][0]["snippet"])

    def test_skill_markdown_single_file_is_supported(self) -> None:
        result = audit(FIXTURES / "safe_skill" / "SKILL.md")
        self.assertEqual(result["input"]["type"], "skill_markdown")

    def test_mcp_json_is_supported(self) -> None:
        result = audit(FIXTURES / "mcp" / "mcp.json")
        self.assertEqual(result["input"]["type"], "mcp_json")
        ids = {item["id"] for item in result["findings"]}
        self.assertIn("SEC001", ids)
        self.assertIn("MCP001", ids)

    def test_skill_zip_is_supported_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skill.zip"
            with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.write(FIXTURES / "safe_skill" / "SKILL.md", "safe-skill/SKILL.md")
                archive.write(
                    FIXTURES / "safe_skill" / "tests" / "cases.json",
                    "safe-skill/tests/cases.json",
                )
            result = audit(target)
            self.assertEqual(result["input"]["type"], "skill_zip")
            self.assertEqual(result["summary"]["findings"], 0)

    def test_zip_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("../escape.txt", "not executed")
            with self.assertRaises(UnsafeInputError):
                load_input(target)

    def test_zip_symlink_and_binary_text_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "odd.zip"
            with zipfile.ZipFile(target, "w") as archive:
                link = zipfile.ZipInfo("skill/link.txt")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, "SKILL.md")
                archive.writestr("skill/blob.txt", b"\x00\x01\x02")
                archive.writestr("skill/SKILL.md", "# Demo\nLocal-only example.\n")
            loaded = load_input(target)
            reasons = {item.reason for item in loaded.skipped_files}
            self.assertIn("symlink entry skipped", reasons)
            self.assertIn("binary or non-UTF text skipped", reasons)

    def test_corrupt_zip_is_rejected_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "broken.zip"
            target.write_bytes(b"not a zip")
            with self.assertRaises(UnsafeInputError):
                load_input(target)

    def test_unknown_json_is_rejected_as_mcp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unknown.json"
            target.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
            with self.assertRaises(UnsafeInputError):
                load_input(target)


if __name__ == "__main__":
    unittest.main()
