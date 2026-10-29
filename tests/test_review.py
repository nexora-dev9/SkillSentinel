from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from engine.report import render_report
from engine.review import ReviewError, attach_review, review_template
from engine.scanner import audit

ROOT = Path(__file__).resolve().parents[1]


def completed_review(result: dict) -> dict:
    review = review_template(result)
    review.update(declared_purpose="Inert scanner fixture", consistency="consistent", rationale="Evidence consists of inert examples; no target was executed.")
    for finding in review["finding_reviews"]:
        finding.update(classification="inert", rationale="Reviewed as an inert artificial fixture; this is not a runtime guarantee.")
    return review


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.result = audit(ROOT / "demo/cases/04_auto_repairable")

    def test_pending_template_is_not_a_completed_review(self):
        with self.assertRaises(ReviewError):
            attach_review(self.result, review_template(self.result))

    def test_valid_review_is_bound_and_preserves_static_evidence(self):
        result = attach_review(self.result, completed_review(self.result))
        self.assertEqual(result["decision"]["status"], "semantic_reviewed")
        self.assertEqual(result["findings"], self.result["findings"])
        self.assertNotIn("semantic_review", self.result)

    def test_stale_input_and_changed_evidence_rejected(self):
        review = completed_review(self.result)
        changed = copy.deepcopy(self.result)
        changed["input"]["sha256"] = "0" * 64
        with self.assertRaises(ReviewError):
            attach_review(changed, review)
        changed = copy.deepcopy(self.result)
        changed["findings"][0]["severity"] = "low"
        with self.assertRaises(ReviewError):
            attach_review(changed, review)

    def test_omitted_duplicate_and_unknown_evidence_rejected(self):
        valid = completed_review(self.result)
        for entries in (valid["finding_reviews"][:-1], valid["finding_reviews"] + valid["finding_reviews"][:1], [{"key": "foreign", "classification": "inert", "rationale": "fake"}]):
            with self.subTest(entries=entries):
                review = copy.deepcopy(valid)
                review["finding_reviews"] = entries
                with self.assertRaises(ReviewError):
                    attach_review(self.result, review)

    def test_uncertainty_and_partial_coverage_prevent_proceed(self):
        review = completed_review(self.result)
        review["installation_recommendation"] = "PROCEED WITH CAUTION"
        review["finding_reviews"][0]["classification"] = "uncertain"
        with self.assertRaises(ReviewError):
            attach_review(self.result, review)
        partial = copy.deepcopy(self.result)
        partial["coverage"]["complete"] = False
        review = completed_review(partial)
        review["installation_recommendation"] = "PROCEED WITH CAUTION"
        with self.assertRaises(ReviewError):
            attach_review(partial, review)

    def test_unnecessary_high_risk_requires_block(self):
        review = completed_review(self.result)
        key = next(f["key"] for f in self.result["findings"] if f["id"] == "OUT001")
        next(f for f in review["finding_reviews"] if f["key"] == key)["classification"] = "unnecessary"
        with self.assertRaises(ReviewError):
            attach_review(self.result, review)
        review["installation_recommendation"] = "BLOCK"
        self.assertEqual(attach_review(self.result, review)["decision"]["installation_recommendation"], "BLOCK")

    def test_legacy_semantics_are_not_claimed_as_validated(self):
        result = copy.deepcopy(self.result)
        result["semantic_review"] = {"consistency": "consistent"}
        report = render_report(result)
        self.assertIn("unreviewed", report)
        self.assertIn("旧格式", report)

    def test_html_escapes_untrusted_evidence_and_sanitizes_review(self):
        result = copy.deepcopy(self.result)
        result["findings"][0]["evidence"][0]["snippet"] = '<script>alert("bad")</script>'
        review = completed_review(result)
        review["rationale"] = "API_KEY='FAKE_REVIEW_KEY_123'; <img src=x onerror=alert(1)>"
        reviewed = attach_review(result, review)
        self.assertNotIn("FAKE_REVIEW_KEY_123", json.dumps(reviewed))
        report = render_report(reviewed)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img src=x", report)
        self.assertIn("&lt;script&gt;", report)

    def test_unrelated_repair_report_rejected(self):
        with self.assertRaises(ValueError):
            render_report(self.result, {"source_sha256": "0" * 64})


if __name__ == "__main__":
    unittest.main()
