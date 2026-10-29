from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .redaction import redact_data, redact_text
from .repair import RepairError, apply_patch_plan, build_patch_plan
from .report import render_report
from .review import attach_review, review_template
from .safe_reader import MAX_TOTAL_BYTES, UnsafeInputError
from .scanner import audit


def read_record(path: str) -> dict:
    target = Path(path).expanduser()
    with target.open("rb") as stream:
        raw = stream.read(MAX_TOTAL_BYTES + 1)
    if len(raw) > MAX_TOTAL_BYTES:
        raise ValueError("JSON record exceeds the size limit.")
    result = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object.")
    return result


def write_output(payload: str, output: str | None, source: str | None = None) -> None:
    if not output:
        print(payload, end="")
        return
    target = Path(output).expanduser().resolve()
    if source:
        original = Path(source).expanduser().resolve()
        if target == original or (original.is_dir() and target.is_relative_to(original)):
            raise ValueError("Results must be written outside the audited input.")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    print(target)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SkillSentinel: non-executing Skill/MCP audit, review, and copy repair")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("audit", help="Read and scan an untrusted Skill or MCP configuration")
    scan.add_argument("source")
    scan.add_argument("-o", "--output")
    scan.add_argument("--fail-on", choices=("high", "medium"), help="Return 1 if this severity or higher is present")
    plan = commands.add_parser("plan", help="Create a snapshot-bound plan without modifying the input")
    plan.add_argument("source")
    plan.add_argument("-o", "--output")
    repair = commands.add_parser("repair", help="Apply an approved saved plan to a new copy")
    repair.add_argument("source")
    repair.add_argument("--plan", required=True, help="The exact plan already shown to and approved by the user")
    repair.add_argument("-o", "--output-dir", "--output", dest="output_dir", required=True)
    repair.add_argument("--confirm", action="store_true")
    template = commands.add_parser("review-template", help="Create a structured review template for a saved audit")
    template.add_argument("audit")
    template.add_argument("-o", "--output")
    review = commands.add_parser("review", help="Validate and attach an agent or human review")
    review.add_argument("audit")
    review.add_argument("--review", required=True)
    review.add_argument("-o", "--output")
    report = commands.add_parser("report", help="Render an offline report from actual saved results")
    report.add_argument("audit")
    report.add_argument("--repair-report")
    report.add_argument("-o", "--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    argv = list(sys.argv[1:] if argv is None else argv)
    commands = {"audit", "plan", "repair", "review-template", "review", "report"}
    if argv and not argv[0].startswith("-") and argv[0] not in commands:
        argv.insert(0, "audit")
    args = build_parser().parse_args(argv)
    try:
        if args.command == "audit":
            result = audit(args.source)
        elif args.command == "plan":
            result = build_patch_plan(args.source)
        elif args.command == "repair":
            result = apply_patch_plan(args.source, args.output_dir, confirmed=args.confirm, patch_plan=read_record(args.plan))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        else:
            result = read_record(args.audit)
            if not isinstance(result.get("findings"), list) or not isinstance(result.get("input"), dict):
                raise ValueError("Expected an audit record with input and findings.")
            if args.command == "review-template":
                result = review_template(result)
            elif args.command == "review":
                result = attach_review(result, read_record(args.review))
            else:
                repair = read_record(args.repair_report) if args.repair_report else None
                write_output(render_report(result, repair), args.output, result["input"].get("source", args.audit))
                return 0
        payload = json.dumps(redact_data(result), ensure_ascii=False, indent=2) + "\n"
        original = getattr(args, "source", None) or result.get("input", {}).get("source", getattr(args, "audit", None))
        write_output(payload, args.output, original)
        if args.command == "audit" and args.fail_on:
            severities = {"high"} if args.fail_on == "high" else {"high", "medium"}
            return int(any(f["severity"] in severities for f in result["findings"]))
        return 0
    except (OSError, ValueError, UnsafeInputError, RepairError) as exc:
        print("SkillSentinel error: " + redact_text(str(exc)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
