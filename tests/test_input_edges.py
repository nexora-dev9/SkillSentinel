from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.scanner import audit
from engine.safe_reader import MAX_FILE_BYTES, UnsafeInputError, load_input
from test_security import make_skill


class InputEdgeTests(unittest.TestCase):
    def test_parse_failure_keeps_review_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), script="def missing_colon()\n    pass\n")
            result = audit(source)
            self.assertIn("PAR001", {f["id"] for f in result["findings"]})
            self.assertEqual(result["decision"]["installation_recommendation"], "REVIEW")

    def test_bearer_and_generic_token_generate_secret_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = make_skill(Path(tmp), body="Authorization: Bearer FAKE_BEARER_123\nTOKEN=FAKE_TOKEN_123\n")
            result = audit(source)
            self.assertTrue({"SEC001", "SEC002"} <= {f["id"] for f in result["findings"]})
            self.assertNotIn("FAKE_BEARER_123", json.dumps(result))
            self.assertNotIn("FAKE_TOKEN_123", json.dumps(result))

    def test_multiple_mcp_servers_have_distinct_correct_pointers(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "mcp.json"
            source.write_text(json.dumps({"mcpServers": {"one": {"command": "python"}, "two": {"command": "node"}}}), encoding="utf-8")
            findings = [f for f in audit(source)["findings"] if f["id"] == "MCP001"]
            self.assertEqual({f["evidence"][0]["pointer"] for f in findings}, {"/mcpServers/one/command", "/mcpServers/two/command"})
            self.assertEqual(len(findings), 2)

    def test_empty_server_does_not_receive_clear_triage(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "mcp.json"
            source.write_text('{"mcpServers":{"empty":{}}}', encoding="utf-8")
            self.assertEqual(audit(source)["decision"]["installation_recommendation"], "REVIEW")

    def test_size_and_finding_limits_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input.txt"
            source.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            with self.assertRaises(UnsafeInputError):
                load_input(source)
            source.write_text("https://example.invalid\n" * 5001, encoding="utf-8")
            with self.assertRaises(UnsafeInputError):
                audit(source)


if __name__ == "__main__":
    unittest.main()
