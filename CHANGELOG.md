# Changelog

## 0.2.0

- Credential redaction applies to all evidence and recognized value reuse.
- Evidence identifies Python calls, literals, comments, documentation, and
  configuration; AST inspection handles common aliases and multiline calls.
- Negated or example-only guardrail text does not satisfy confirmation checks.
- Added structured, snapshot-bound semantic review and generic offline reports.
- Repair requires the approved saved plan; changed input or plan aborts delivery.
- Generated tests remain explicitly marked as drafts requiring manual validation.
- Added content manifests, ZIP portability checks, Windows junction handling,
  standalone package installation, a unified CLI, and release tooling.

Breaking changes: repair/apply requires `--plan`; output files are created
exclusively rather than overwritten. Old audit JSON remains reportable as
unvalidated evidence, but must be regenerated for review or bound repair.

## 0.1.1

Local competition prototype: static scanning, copy repair, and newline
preservation. Historical competition evidence is retained separately.
