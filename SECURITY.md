# Security policy

SkillSentinel is a non-executing pre-install review tool. It cannot certify a
Skill, executable, dependency, remote endpoint, or MCP server as safe.

## Boundaries

- Target files are read as data. Target scripts, commands, binaries, install
  hooks, and MCP servers are never started by the scanner or repairer.
- Python token and AST inspection distinguishes syntax and common import
  aliases. It does not establish runtime reachability or perform complete
  data-flow analysis. Other languages currently use text rules.
- Symlinks and Windows reparse points are skipped and reported. ZIP traversal,
  duplicate names, Windows device names, ADS paths, and size limits are checked.
- Unsupported/binary/non-UTF files are visible in coverage. A partial audit
  cannot receive a validated PROCEED WITH CAUTION recommendation.
- Redaction covers credential assignments, Bearer headers, URL credentials,
  token query parameters, and reuse of recognized values. Arbitrary encoded,
  encrypted, fragmented, or otherwise unrecognized secrets may not be detected.
  Treat audit results and repaired archives as confidential.
- Repair only appends documentation and creates draft test scaffolds in a copy.
  It does not remove executable risks. Original credentials may remain in that
  copy and archive; redacting a report is not repairing credentials.
- A saved plan and explicit confirmation are required. Content fingerprints
  bind input, plan, copy, and report. Concurrent changes detected during repair
  abort delivery. This is not an OS sandbox or protection against a hostile
  process controlling the same filesystem.
- Semantic review validation verifies schema, evidence coverage, and identity;
  the reviewing agent or human remains responsible for the judgment.

## Reporting a vulnerability

Use the repository's private vulnerability reporting feature when enabled.
Otherwise open an issue containing only a non-sensitive summary and ask for a
private contact route. Never post real credentials or confidential inputs.
Include the version, input format, minimal inert reproducer, expected behavior,
and observed behavior. Do not execute untrusted targets to demonstrate a bug.
