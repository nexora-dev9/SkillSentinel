from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.review import attach_review, review_template, ReviewError  # noqa: E402
from engine.scanner import audit  # noqa: E402


def evaluate(output: Path, reviews: Path | None = None) -> dict:
    dataset_path = ROOT / "evaluation/cases.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for case in dataset["cases"]:
        source = output / "cases" / case["id"]
        source.mkdir(parents=True)
        document = "---\nname: paired-fixture\ndescription: " + case["purpose"] + "\n---\n# Instructions\n" + case["body"]
        document += "\n明确用户确认后执行外发与修改；用户拒绝则停止。\nFallback: stop on failure.\n"
        (source / "SKILL.md").write_text(document, encoding="utf-8")
        if case["script"]:
            (source / "scripts").mkdir()
            (source / "scripts/example.py").write_text(case["script"], encoding="utf-8")
        (source / "tests").mkdir()
        tests = {"skill": "paired-fixture", "version": "1.0.0", "test_cases": [{"category": "happy_path"}, {"category": "negative"}]}
        (source / "tests/cases.json").write_text(json.dumps(tests), encoding="utf-8")
        result = audit(source)
        audit_path = output / "audits" / f"{case['id']}.json"
        audit_path.parent.mkdir(exist_ok=True)
        audit_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        template_path = output / "review_templates" / f"{case['id']}.json"
        template_path.parent.mkdir(exist_ok=True)
        template_path.write_text(json.dumps(review_template(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        actual = {f["id"] for f in result["findings"]}
        origins = {rule: {ev["origin"] for f in result["findings"] if f["id"] == rule for ev in f["evidence"]} for rule in case.get("origins", {})}
        static_passed = actual == set(case["expected_ids"]) and all(set(expected) <= origins[rule] for rule, expected in case.get("origins", {}).items())
        record = {"id": case["id"], "pair": case["pair"], "audit": str(audit_path), "source": str(source),
                  "finding_ids": sorted(actual), "static_passed": static_passed,
                  "expected_consistency": case["consistency"], "expected_recommendation": case["recommendation"],
                  "semantic_status": "not_run", "semantic_correct": None}
        if reviews and (reviews / f"{case['id']}.json").exists():
            try:
                review = json.loads((reviews / f"{case['id']}.json").read_text(encoding="utf-8"))
                reviewed = attach_review(result, review)
                record["semantic_status"] = "validated"
                record["semantic_correct"] = reviewed["decision"]["consistency"] == case["consistency"] and reviewed["decision"]["installation_recommendation"] == case["recommendation"]
            except (ReviewError, ValueError, OSError) as exc:
                record["semantic_status"] = "invalid"
                record["semantic_error"] = str(exc)
        records.append(record)
    reviewed = [r for r in records if r["semantic_status"] == "validated"]
    report = {"schema_version": 1, "dataset_sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
              "cases": records, "static_passed": sum(r["static_passed"] for r in records), "total": len(records),
              "semantic_reviewed": len(reviewed), "semantic_correct": sum(bool(r["semantic_correct"]) for r in reviewed),
              "semantic_accuracy": sum(bool(r["semantic_correct"]) for r in reviewed) / len(records) if len(reviewed) == len(records) else None,
              "note": "Static checks and human semantic labels are separate. Model accuracy is only reported for a complete validated review set."}
    (output / "evaluation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and evaluate inert paired audit cases")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reviews", type=Path, help="Directory of actual agent/human reviews named CASE_ID.json")
    args = parser.parse_args()
    result = evaluate(args.output_dir, args.reviews)
    print(json.dumps({k: result[k] for k in ("static_passed", "total", "semantic_reviewed", "semantic_accuracy")}))
    return int(result["static_passed"] != result["total"] or any(c["semantic_correct"] is False or (args.reviews and c["semantic_status"] != "validated") for c in result["cases"]))


if __name__ == "__main__":
    raise SystemExit(main())
