# SkillSentinel

**Non-executing Skill/MCP pre-install audit, evidence-bound review, and conservative copy repair.**

**English** | [简体中文](README.zh-CN.md)

SkillSentinel is designed for individuals and teams evaluating third-party Agent Skills or MCP configurations before adoption. It reads files and locates risk evidence, lets an Agent or human reviewer judge whether observed capabilities match the declared purpose, and, after explicit confirmation, can add safe documentation constraints and draft test scaffolding to a copy before producing reproducible reports.

Python 3.10+ · No runtime third-party dependencies · MIT

## What it does

- Inputs: `SKILL.md`, local Skill directories, Skill ZIP archives, and MCP JSON.
- Static evidence: credentials, process execution, network targets, potential exfiltration, sensitive paths, instruction overrides, and structural or quality issues.
- Python evidence distinguishes calls, strings, and comments, including common import aliases and multiline calls; other languages currently use text rules.
- Content fingerprints bind audits, per-finding semantic reviews, approved plans, repaired copies, and reports.
- Generates offline HTML reports, redacted diffs, repaired ZIP archives, and before/after audit JSON.
- Repair is deliberately conservative: it only adds documentation and draft tests while preserving unresolved capability risks and manual-review items.

The scanner does **not** execute the target, connect to MCP endpoints, or install target dependencies. Its output is a pre-install review recommendation, not a security certification. See [SECURITY.md](SECURITY.md) for the full boundary model.

## Install the standalone CLI

From the repository root:

```text
python -m pip install .
skillsentinel --version
```

You can also run every command directly from source by replacing `skillsentinel` with `python -m engine.cli`.

## Install the DuMate Skill

```text
python skill/build_skill.py
```

Import `artifacts/skillsentinel_build/skillsentinel.zip` through DuMate's Skill installation entry point.
The ZIP bundles the same engine and license and only requires Python 3.10+.
`skill/skillsentinel/` is the build template; install the generated complete ZIP rather than the template directory, which does not contain the bundled engine copy.

Suggested trigger prompts include: “Check whether this Skill is safe to install” and “Audit this MCP configuration.”
Model judgment, confirmation interaction, and final explanation are handled by the host Agent; the engine itself does not depend on a specific model service.

## Quick start: audit, plan, confirm, repair, report

Write all outputs to a new directory outside the target. Existing outputs are never overwritten.

```text
skillsentinel audit demo/cases/04_auto_repairable --output out/audit.json
skillsentinel plan demo/cases/04_auto_repairable --output out/patch_plan.json
```

After reviewing the plan and confirming that only documentation constraints and draft test scaffolding should be added, run:

```text
skillsentinel repair demo/cases/04_auto_repairable --plan out/patch_plan.json --output-dir out/repair --confirm
skillsentinel report out/audit.json --repair-report out/repair/repair_report.json --output out/report.html
```

Repair output includes `before_audit.json`, `after_audit.json`, `repair_report.json`, `repair.diff`, `patched_skill/`, and `patched_skill.zip`.
The original source hash must remain unchanged; repair aborts if the input, approved plan, or copied content changes. `--confirm` is the caller's declaration that explicit user approval was obtained. The CLI cannot prove that the user actually reviewed the plan.

Generated `tests/cases.json` files are marked `requires_manual_validation: true`, and rescanning preserves `TST004`.
Adding test scaffolding is never treated as a successful behavioral test and does not claim that exfiltration or execution risks were fixed.

## Structured semantic review

```text
skillsentinel review-template out/audit.json --output out/review.json
```

An Agent or human reviewer fills in the declared purpose, purpose/capability consistency, installation recommendation, and a classification plus rationale for each required finding.
Classifications are `necessary / unnecessary / inert / uncertain`; installation recommendations are `BLOCK / REVIEW / PROCEED WITH CAUTION`.
See the [review protocol](skill/skillsentinel/references/REVIEW_FORMAT.md) for the current structured format.

```text
skillsentinel review out/audit.json --review out/review.json --output out/reviewed_audit.json
skillsentinel report out/reviewed_audit.json --output out/reviewed_report.html
```

Validation rejects snapshot mismatches, missing evidence, duplicate entries, and recommendations that conflict with the risk policy.
It verifies schema and evidence binding, not the correctness of semantic judgment. Unreviewed reports are explicitly marked `unreviewed`, and legacy Agent output is not treated as validated judgment.

## CLI and exit codes

`audit`, `plan`, `repair`, `review-template`, `review`, and `report` support `--help`.

```text
skillsentinel audit path/to/skill --fail-on high --output out/ci_audit.json
```

- `0`: command completed; this does **not** mean the input is safe.
- `1`: `audit --fail-on` reached the requested static severity threshold.
- `2`: argument, input, confirmation, review, plan, or output error.

Automatic repair supports only a local directory containing one clear Skill root. ZIP archives, single documents, and MCP inputs are audit-only.
Read limits: 300 files/ZIP entries, 2 MiB per file, 20 MiB total. Skipped content is reported explicitly; directory links and Windows junctions are not traversed.

## Development and validation

```text
python -m unittest discover -s tests -v
python demo/run_validation.py --output-dir out/demo_validation
python tools/evaluate_pairs.py --output-dir out/paired_evaluation
python tools/build_release.py
```

Tests cover redaction, evidence origin, input boundaries, review contracts, confirmation gates, snapshot changes, format preservation, source protection, CLI behavior, and the standalone Skill ZIP.
Paired examples contain static expectations and human semantic labels. The evaluation script reports only metrics that were actually executed; without Agent review output, it does not invent model-accuracy numbers.
GitHub CI runs a Windows/Linux and Python-version matrix. Local validation results are not presented as remote CI results.

The release tool generates a complete Skill ZIP, a source ZIP suitable for GitHub publication, and a SHA-256 manifest.
The public source package excludes machine records, historical delivery artifacts, competition PDFs, screenshots, and real credentials.

## Project layout

```text
engine/                Standard-library audit, review, repair, reporting, and CLI
skill/skillsentinel/   Skill template, decision policy, and review protocol
skill/build_skill.py   Bundles the same engine into a standalone Skill
tests/                 Non-executing regression and integration tests
demo/                  Six intentionally harmless demonstration classes
evaluation/            Paired examples and semantic labels
tools/                 Evaluation, validation, and release tooling
docs/                  Local competition material; excluded from public releases
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md) for development details. All demo credentials are synthetic test values, and unknown target scripts are never executed.
