from __future__ import annotations

import json
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.repair import apply_patch_plan, build_patch_plan  # noqa: E402
from engine.scanner import audit  # noqa: E402


MATRIX_PATH = ROOT / "demo" / "VALIDATION_MATRIX.json"
OUTPUT_ROOT = ROOT / "artifacts" / "validation_v020"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the inert demo validation suite without overwriting previous evidence")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_dir.resolve()
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    output_root.mkdir(parents=True, exist_ok=False)

    results: list[dict] = []
    for case in matrix["cases"]:
        source = ROOT / case["source"]
        result = audit(source)
        ids = [item["id"] for item in result["findings"]]
        missing = sorted(set(case["expected_ids"]) - set(ids))
        unexpected = sorted(set(ids) - set(case["expected_ids"]))
        plan = build_patch_plan(source)
        record = {
            "id": case["id"],
            "source": case["source"],
            "summary": result["summary"],
            "finding_ids": ids,
            "expected_ids": case["expected_ids"],
            "missing_expected_ids": missing,
            "unexpected_ids": unexpected,
            "semantic_expectation": case["semantic_expectation"],
            "repair_operations": [item["id"] for item in plan.get("operations", [])],
            "passed": not missing and not unexpected and bool(plan.get("operations")) == bool(case["repair_expected"]),
            "semantic_evaluation": "not_run; semantic_expectation is a human-review label, not a scored model result",
        }
        results.append(record)

        audit_path = output_root / f"{case['id']}_audit.json"
        audit_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    demo_source = ROOT / "demo" / "cases" / "04_auto_repairable"
    repair_result = apply_patch_plan(demo_source, output_root / "04_auto_repairable_repair", confirmed=True, patch_plan=build_patch_plan(demo_source))

    report = {
        "schema_version": 1,
        "execution_policy": "All demo inputs are inert, artificial fixtures; target scripts are never executed.",
        "cases": results,
        "all_cases_passed": all(item["passed"] for item in results),
        "main_demo_repair": {
            "before": repair_result["before"],
            "after": repair_result["after"],
            "remaining_findings": repair_result["remaining_findings"],
            "output": str(output_root / "04_auto_repairable_repair")
        }
    }
    (output_root / "validation_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(output_root / "validation_report.json")
    return 0 if report["all_cases_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
