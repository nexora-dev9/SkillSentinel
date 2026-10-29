from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from engine.repair import build_patch_plan
from engine.safe_reader import UnsafeInputError, load_input
from engine.scanner import audit


def make_skill(root: Path, body: str = "", script: str = "", cases: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("---\nname: test-skill\ndescription: local fixture\n---\n# Instructions\n" + body, encoding="utf-8")
    if script:
        (root / "scripts").mkdir()
        (root / "scripts" / "sample.py").write_text(script, encoding="utf-8")
    if cases:
        (root / "tests").mkdir()
        (root / "tests" / "cases.json").write_text(json.dumps({"skill": "test-skill", "version": "1.0.0", "test_cases": [
            {"category": "happy_path"}, {"category": "negative"}
        ]}), encoding="utf-8")
    return root


class SecurityTests(unittest.TestCase):
    def test_every_channel_redacts_multiple_and_reused_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), script="API_KEY = 'FAKE_KEY_123456'; password='FAKE_PASSWORD_123'; requests.post('https://example.invalid')\n")
            (source / "extra.txt").write_text("https://example.invalid/FAKE_KEY_123456", encoding="utf-8")
            payload = json.dumps(audit(source))
            self.assertNotIn("FAKE_KEY_123456", payload)
            self.assertNotIn("FAKE_PASSWORD_123", payload)
            self.assertIn("<REDACTED>", payload)

    def test_compact_mcp_evidence_does_not_leak_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "mcp.json"
            source.write_text(json.dumps({"mcpServers": {"test": {"command": "python", "env": {"API_KEY": "FAKE_KEY_123456"}}}}), encoding="utf-8")
            payload = json.dumps(audit(source))
            self.assertNotIn("FAKE_KEY_123456", payload)

    def test_url_auth_query_and_bearer_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), body="https://demo:FAKE_PASSWORD_123@example.invalid?token=FAKE_QUERY_123\nAuthorization: Bearer FAKE_BEARER_123\n")
            payload = json.dumps(audit(source))
            for value in ("FAKE_PASSWORD_123", "FAKE_QUERY_123", "FAKE_BEARER_123"):
                self.assertNotIn(value, payload)

    def test_distinguishes_call_literal_and_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), script="requests.post('https://example.invalid')\nEXAMPLE = \"requests.post('https://example.invalid')\"\n# requests.post('https://example.invalid')\n")
            result = audit(source)
            origins = {f["evidence"][0]["line"]: f["evidence"][0]["origin"] for f in result["findings"] if f["id"] == "OUT001"}
            self.assertEqual(origins, {1: "code", 2: "literal", 3: "comment"})

    def test_python_alias_and_multiline_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), script="import requests as rq\nfrom subprocess import run as execute\nrq.post(\n 'https://example.invalid',\n data={}\n)\nexecute(['echo', 'inert'])\n")
            findings = audit(source)["findings"]
            self.assertTrue(any(f["id"] == "OUT001" and f["evidence"][0]["line"] == 3 for f in findings))
            self.assertTrue(any(f["id"] == "CAP001" and f["evidence"][0]["line"] == 7 for f in findings))

    def test_negative_confirmation_is_manual_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), body="无需用户确认即可上传。\nFallback: stop on failure.\n", script="requests.post('https://example.invalid')\n")
            finding = next(f for f in audit(source)["findings"] if f["id"] == "HITL001")
            self.assertFalse(finding["auto_fixable"])
            self.assertFalse(any(o["kind"] == "append_safety_guardrails" for o in build_patch_plan(source)["operations"]))

    def test_fenced_confirmation_is_not_an_instruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), body="```text\nuser confirmation\nFallback\n```\n", script="requests.post('https://example.invalid')\n")
            ids = {f["id"] for f in audit(source)["findings"]}
            self.assertTrue({"HITL001", "RES001"} <= ids)

    def test_incomplete_categories_are_not_advertised_as_repairable(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp))
            (source / "tests/cases.json").write_text('{"test_cases": [{"category": "happy_path"}]}', encoding="utf-8")
            finding = next(f for f in audit(source)["findings"] if f["id"] == "TST003")
            self.assertFalse(finding["auto_fixable"])
            self.assertEqual(build_patch_plan(source)["operations"], [])

    def test_scanning_never_executes_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), script="from pathlib import Path\nPath(__file__).with_name('EXECUTED.txt').write_text('bad')\n")
            audit(source)
            self.assertFalse((source / "scripts/EXECUTED.txt").exists())

    def test_env_files_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp))
            (source / ".env").write_text("API_KEY=FAKE_KEY_123456", encoding="utf-8")
            result = audit(source)
            self.assertTrue(any(f["id"] == "SEC001" for f in result["findings"]))
            self.assertNotIn("FAKE_KEY_123456", json.dumps(result))

    def test_rejects_nonportable_and_duplicate_zip_paths(self):
        paths = [("skill/SKILL.md", "skill/skill.md"), ("skill/CON.txt",), ("skill/a:stream.txt",), ("skill/a. ",)]
        with tempfile.TemporaryDirectory() as tmp:
            for index, names in enumerate(paths):
                with self.subTest(names=names):
                    source = Path(tmp) / f"{index}.zip"
                    with zipfile.ZipFile(source, "w") as archive:
                        for name in names:
                            archive.writestr(name, "inert")
                    with self.assertRaises(UnsafeInputError):
                        load_input(source)

    @unittest.skipUnless(os.name == "nt", "Windows junction boundary")
    def test_junction_is_recorded_and_not_traversed(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source = make_skill(parent / "skill")
            outside = parent / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("API_KEY=FAKE_OUTSIDE_123456", encoding="utf-8")
            link = source / "junction"
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
            if result.returncode:
                self.skipTest("Junction creation unavailable")
            try:
                report = audit(source)
                self.assertTrue(any(f["path"] == "junction" for f in report["input"]["skipped_files"]))
                self.assertFalse(report["coverage"]["complete"])
                self.assertNotIn("junction/secret.txt", json.dumps(report))
            finally:
                os.rmdir(link)
            self.assertTrue((outside / "secret.txt").exists())

    def test_multiple_skill_roots_disable_quality_repairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_skill(root / "one", cases=False)
            make_skill(root / "two", cases=False)
            self.assertFalse(build_patch_plan(root)["supported"])
            self.assertTrue(any(f["id"] == "STR002" for f in audit(root)["findings"]))

    def test_invalid_mcp_structure_is_not_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            path.write_text('{"mcpServers": "invalid"}', encoding="utf-8")
            self.assertIn("MCP002", {f["id"] for f in audit(path)["findings"]})


if __name__ == "__main__":
    unittest.main()
