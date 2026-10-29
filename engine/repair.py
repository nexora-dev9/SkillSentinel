from __future__ import annotations

import difflib
import json
import hashlib
import os
import re
import shutil
import zipfile
import tempfile
from pathlib import Path

from .safe_reader import is_link, load_input
from .redaction import redact_data, redact_text, secret_values
from .scanner import audit


class RepairError(RuntimeError):
    """Base error for conservative repair operations."""


class RepairConfirmationRequired(RepairError):
    """Raised when a repair is requested without explicit confirmation."""


class RepairUnsupportedInput(RepairError):
    """Raised when automatic repair is intentionally unsupported."""


def _extract_skill_name(skill_text: str, fallback: str) -> str:
    match = re.search(r"(?m)^\s*name\s*:\s*[\"']?([^\s\"']+)", skill_text)
    return match.group(1) if match else fallback


def _skill_relative_path(source: Path) -> Path | None:
    candidates: list[Path] = []
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        dirs[:] = [name for name in dirs if not is_link(root_path / name)]
        for name in files:
            if name.lower() == "skill.md":
                candidates.append((root_path / name).relative_to(source))
    if len(candidates) == 1:
        return candidates[0]
    return None


def _plan_digest(plan: dict) -> str:
    content = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _seal_plan(plan: dict) -> dict:
    plan["plan_sha256"] = _plan_digest(plan)
    return plan


def build_patch_plan(source: str | Path) -> dict:
    source_path = Path(source).expanduser().resolve()
    before = audit(source_path)
    operations: list[dict] = []
    finding_ids = {item["id"] for item in before["findings"] if item.get("auto_fixable")}
    common = {"schema_version": 1, "source": str(source_path), "source_sha256": before["input"]["sha256"],
              "input_type": before["input"]["type"], "before_summary": before["summary"]}

    if before["input"]["type"] != "skill_directory":
        return _seal_plan({
            **common,
            "supported": False,
            "reason": "Automatic repair is limited to a local Skill directory; other inputs are audit-only.",
            "operations": [],
            "before_summary": before["summary"],
        })

    skill_rel = _skill_relative_path(source_path)
    if skill_rel is None:
        return _seal_plan({**common, "supported": False, "reason": "Repair requires exactly one SKILL.md root.", "operations": []})
    cases_rel = skill_rel.parent / "tests" / "cases.json"
    if "TST001" in finding_ids:
        operations.append(
            {
                "id": "FIX-TST001",
                "finding_id": "TST001",
                "kind": "create_cases",
                "target": cases_rel.as_posix(),
                "description": "Create a DuMate-format happy_path + negative test skeleton.",
            }
        )

    safety_needs: list[str] = []
    if "HITL001" in finding_ids:
        safety_needs.append("confirmation")
    if "RES001" in finding_ids:
        safety_needs.append("fallback")
    if safety_needs and skill_rel is not None:
        operations.append(
            {
                "id": "FIX-SAFETY-GUARDRAILS",
                "finding_ids": [item for item in ("HITL001", "RES001") if item in finding_ids],
                "kind": "append_safety_guardrails",
                "target": skill_rel.as_posix(),
                "requirements": safety_needs,
                "description": "Append conservative confirmation/fallback requirements without altering existing logic.",
            }
        )

    return _seal_plan({
        **common,
        "supported": True,
        "operations": operations,
        "before_summary": before["summary"],
        "non_auto_fix_findings": [
            item["id"] for item in before["findings"] if not item.get("auto_fixable", False)
        ],
    })


def _assert_no_symlinks(source: Path) -> None:
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in [*dirs, *files]:
            candidate = root_path / name
            if is_link(candidate):
                raise RepairUnsupportedInput(
                    f"automatic repair refuses directories containing symlinks: {candidate.relative_to(source)}"
                )


def _read_utf8_preserve_format(path: Path) -> tuple[str, bytes, str]:
    """Read UTF-8 text while retaining BOM and the existing newline convention."""
    raw = path.read_bytes()
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    content = raw[len(bom) :]
    text = content.decode("utf-8")
    if b"\r\n" in content:
        newline = "\r\n"
    elif b"\r" in content and b"\n" not in content:
        newline = "\r"
    else:
        newline = "\n"
    return text, bom, newline


def _write_utf8_preserve_format(path: Path, text: str, bom: bytes) -> None:
    path.write_bytes(bom + text.encode("utf-8"))


def _make_cases(skill_name: str, version: str = "1.0.0") -> str:
    payload = {
        "skill": skill_name,
        "version": version,
        "generated_by": "SkillSentinel",
        "requires_manual_validation": True,
        "test_cases": [
            {
                "id": "TC001",
                "name": "SkillSentinel generated standard trigger case",
                "category": "happy_path",
                "input": {"user_message": f"请使用 {skill_name} 完成一次标准任务"},
                "expected": {"trigger_skill": True},
            },
            {
                "id": "TC002",
                "name": "SkillSentinel generated unrelated non-trigger case",
                "category": "negative",
                "input": {"user_message": "今天天气怎么样？"},
                "expected": {"trigger_skill": False},
            },
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _guardrail_block(requirements: list[str]) -> str:
    lines = ["", "## SkillSentinel Safety Guardrails", ""]
    if "confirmation" in requirements:
        lines.extend(
            [
                "- **Explicit user confirmation:** Before external transmission, process execution with side effects, deletion, or modification of existing data, show the planned action and wait for explicit user confirmation. If the user refuses, do not execute it.",
            ]
        )
    if "fallback" in requirements:
        lines.extend(
            [
                "- **Fallback:** If an external service is unavailable, do not fabricate success. Stop risky external actions, explain what is unavailable, and return only results that can be verified locally.",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _unified_diff(path: str, before: str, after: str) -> str:
    return redact_text("\n".join(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="",
        )
    ))


def _zip_directory(directory: Path, target: Path) -> None:
    root_name = directory.name
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_dir():
                continue
            if is_link(file_path):
                raise RepairUnsupportedInput("refusing to package a symlink in repaired Skill")
            archive.write(file_path, (Path(root_name) / file_path.relative_to(directory)).as_posix())


def apply_patch_plan(
    source: str | Path,
    output_dir: str | Path,
    *,
    confirmed: bool,
    patch_plan: dict | None = None,
) -> dict:
    if not confirmed:
        raise RepairConfirmationRequired("explicit user confirmation is required before modifying a copy")

    source_path = Path(source).expanduser().resolve()
    output_path = Path(output_dir).expanduser().resolve()
    if not isinstance(patch_plan, dict):
        raise RepairError("An approved saved Patch Plan is required; generate plan and pass --plan before repair.")
    if patch_plan.get("plan_sha256") != _plan_digest(patch_plan):
        raise RepairError("Patch Plan integrity check failed.")
    plan = build_patch_plan(source_path)
    if patch_plan != plan:
        raise RepairError("Input or Patch Plan changed after approval; review a new plan before repairing.")
    if not plan["supported"]:
        raise RepairUnsupportedInput(plan["reason"])
    if not source_path.is_dir():
        raise RepairUnsupportedInput("automatic repair requires a local Skill directory")
    if output_path.exists():
        raise RepairError(f"output already exists: {output_path}")
    if output_path.is_relative_to(source_path):
        raise RepairError("repair output must not be created inside the source Skill directory")

    _assert_no_symlinks(source_path)
    loaded = load_input(source_path)
    for skipped in loaded.skipped_files:
        if any(term in skipped.reason for term in ("size limit", "symlink", "reparse", "failed", "non-regular")):
            raise RepairUnsupportedInput(f"repair blocked by skipped input: {skipped.path}: {skipped.reason}")
    if not plan["operations"]:
        raise RepairError("This plan contains no supported automatic fixes.")
    known_secrets = set().union(*(secret_values(f.text) for f in loaded.files))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".skillsentinel-", dir=output_path.parent) as temporary:
        stage = Path(temporary) / "result"
        patched = stage / "patched_skill"
        shutil.copytree(source_path, patched)
        if load_input(patched).metadata["sha256"] != plan["source_sha256"]:
            raise RepairError("Copied input differs from the approved snapshot.")
        before_audit = audit(source_path)
        if before_audit["input"]["sha256"] != plan["source_sha256"]:
            raise RepairError("Source changed while copying; repair aborted.")
        skill_rel = _skill_relative_path(patched)
        skill_text = (patched / skill_rel).read_text(encoding="utf-8-sig")
        skill_name = _extract_skill_name(skill_text, source_path.name)
        version_match = re.search(r"(?m)^\s*version\s*:\s*[\"']?([^\s\"']+)", skill_text)
        version = version_match.group(1) if version_match else "1.0.0"
        diff_parts = []
        for operation in plan["operations"]:
            target = patched / operation["target"]
            if operation["kind"] == "create_cases":
                if target.exists():
                    raise RepairError("Refusing to overwrite existing test cases.")
                target.parent.mkdir(parents=True, exist_ok=True)
                after = _make_cases(skill_name, version)
                target.write_bytes(after.encode("utf-8"))
                diff_parts.append(_unified_diff(operation["target"], "", after))
            elif operation["kind"] == "append_safety_guardrails":
                before, bom, newline = _read_utf8_preserve_format(target)
                block = _guardrail_block(operation["requirements"]).replace("\n", newline)
                separator = "" if before.endswith(("\n", "\r")) else newline
                after = before + separator + block
                _write_utf8_preserve_format(target, after, bom)
                diff_parts.append(_unified_diff(operation["target"], before, after))
        source_after = load_input(source_path).metadata["sha256"]
        if source_after != plan["source_sha256"]:
            raise RepairError("Source changed during repair; output was not delivered.")
        after_audit = audit(patched)
        after_audit["input"]["source"] = str(output_path / "patched_skill")
        remaining_ids = {item["id"] for item in after_audit["findings"]}
        resolved = sorted({item["id"] for item in before_audit["findings"] if item["auto_fixable"]} - remaining_ids)
        diff_text = "\n\n".join(diff_parts).rstrip() + "\n"
        (stage / "repair.diff").write_text(redact_text(diff_text, known_secrets), encoding="utf-8")
        _zip_directory(patched, stage / "patched_skill.zip")
        report = redact_data({
            "schema_version": 2, "source": str(source_path), "source_sha256": source_after,
            "patched_sha256": after_audit["input"]["sha256"], "plan_sha256": plan["plan_sha256"],
            "source_unchanged": True, "patched_directory": str(output_path / "patched_skill"),
            "patched_zip": str(output_path / "patched_skill.zip"), "confirmation_received": True,
            "operations": plan["operations"], "before": before_audit["summary"], "after": after_audit["summary"],
            "resolved_quality_findings": resolved, "runtime_risks_removed": 0,
            "remaining_findings": [item["id"] for item in after_audit["findings"]],
            "note": "Documentation and draft tests were added to a copy. No runtime risk or target behavior was repaired.",
        }, known_secrets)
        for name, data in (("before_audit.json", before_audit), ("after_audit.json", after_audit), ("repair_report.json", report)):
            (stage / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if output_path.exists():
            raise RepairError("Output appeared during repair; refusing to replace it.")
        stage.rename(output_path)
    return report
