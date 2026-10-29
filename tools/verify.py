from __future__ import annotations

import argparse
import json
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_release import source_fingerprint  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real regression tests and save a source-bound result")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/verification_v020.json")
    args = parser.parse_args()
    before = source_fingerprint()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = source_fingerprint()
    success = result.wasSuccessful() and before == after
    report = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
              "source_sha256": before, "source_unchanged": before == after, "tests_run": result.testsRun,
              "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped) - len(result.expectedFailures),
              "failures": [test.id() for test, _ in result.failures], "errors": [test.id() for test, _ in result.errors],
              "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped], "success": success}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return int(not success)


if __name__ == "__main__":
    raise SystemExit(main())
