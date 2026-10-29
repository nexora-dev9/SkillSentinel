"""Bind an agent's structured judgment to the exact audit it reviewed."""
from __future__ import annotations

import copy
import hashlib
import json

from .redaction import redact_data


class ReviewError(ValueError):
    pass


def audit_identity(audit: dict) -> str:
    payload = {"input_sha256": audit.get("input", {}).get("sha256"),
               "scanner": audit.get("scanner", {}).get("version"),
               "coverage": audit.get("coverage"), "findings": audit.get("findings")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def required_findings(audit: dict) -> list[dict]:
    keys = set()
    for finding in audit.get("findings", []):
        if not isinstance(finding, dict) or not isinstance(finding.get("key"), str) or not finding["key"] or finding.get("severity") not in {"high", "medium", "low"} or not isinstance(finding.get("id"), str):
            raise ReviewError("Malformed or legacy finding; re-audit with SkillSentinel 0.2+.")
        if finding["key"] in keys:
            raise ReviewError("Audit contains duplicate evidence keys.")
        keys.add(finding["key"])
    return [f for f in audit.get("findings", []) if f["id"] != "SEM001" and (f.get("semantic_review") or f["severity"] == "high")]


def review_template(audit: dict) -> dict:
    if not audit.get("input", {}).get("sha256"):
        raise ReviewError("Re-audit the input with SkillSentinel 0.2+ before creating a review.")
    return {
        "schema_version": 1,
        "input_sha256": audit["input"]["sha256"],
        "audit_sha256": audit_identity(audit),
        "declared_purpose": "",
        "consistency": "uncertain",
        "installation_recommendation": "REVIEW",
        "rationale": "",
        "finding_reviews": [{"key": f["key"], "classification": "uncertain", "rationale": ""} for f in required_findings(audit)],
    }


def attach_review(audit: dict, review: dict) -> dict:
    if not isinstance(review, dict) or review.get("schema_version") != 1:
        raise ReviewError("Unsupported review schema; use review-template.")
    if not audit.get("input", {}).get("sha256") or review.get("input_sha256") != audit["input"]["sha256"]:
        raise ReviewError("The review does not match the input snapshot.")
    if review.get("audit_sha256") != audit_identity(audit):
        raise ReviewError("The review does not match this audit's evidence and scanner version.")
    for field in ("declared_purpose", "rationale"):
        if not isinstance(review.get(field), str) or not review[field].strip():
            raise ReviewError(f"Review field {field!r} must contain an evidence-based explanation.")
    consistency = review.get("consistency")
    recommendation = review.get("installation_recommendation")
    if consistency not in {"consistent", "inconsistent", "uncertain"}:
        raise ReviewError("consistency must be consistent, inconsistent, or uncertain.")
    if recommendation not in {"BLOCK", "REVIEW", "PROCEED WITH CAUTION"}:
        raise ReviewError("Invalid installation recommendation.")
    expected = {f["key"]: f for f in required_findings(audit)}
    entries = review.get("finding_reviews")
    if not isinstance(entries, list):
        raise ReviewError("finding_reviews must be a list.")
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or item.get("key") not in expected or item["key"] in seen:
            raise ReviewError("Each required finding must be reviewed once; unknown or duplicate keys are rejected.")
        seen.add(item["key"])
        if item.get("classification") not in {"necessary", "unnecessary", "inert", "uncertain"}:
            raise ReviewError("Invalid finding classification.")
        if not isinstance(item.get("rationale"), str) or not item["rationale"].strip():
            raise ReviewError("Each finding requires its own explanation.")
    if seen != set(expected):
        raise ReviewError("The review omits required evidence.")
    if any(item["classification"] == "unnecessary" and expected[item["key"]]["severity"] == "high" for item in entries) and recommendation != "BLOCK":
        raise ReviewError("Unnecessary high-risk capabilities require BLOCK.")
    unresolved = consistency != "consistent" or any(item["classification"] in {"unnecessary", "uncertain"} for item in entries)
    if recommendation == "PROCEED WITH CAUTION" and (unresolved or not audit.get("coverage", {}).get("complete", False)):
        raise ReviewError("Unresolved evidence or incomplete coverage cannot receive PROCEED WITH CAUTION.")
    result = copy.deepcopy(audit)
    result["semantic_review"] = redact_data(review)
    result["decision"] = {"status": "semantic_reviewed", "consistency": consistency,
                          "installation_recommendation": recommendation, "rationale": redact_data(review["rationale"])}
    return result
