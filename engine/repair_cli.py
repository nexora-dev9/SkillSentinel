"""Compatibility entrypoint; apply now requires --plan, just like repair."""
from __future__ import annotations

import sys

from .cli import main as unified_main


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "apply":
        args[0] = "repair"
    return unified_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
