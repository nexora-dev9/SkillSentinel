from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import __version__  # noqa: E402
from skill.build_skill import build  # noqa: E402


def source_files() -> list[Path]:
    names = ["README.md", "README.zh-CN.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "pyproject.toml", ".gitignore",
             "demo/README.md", "demo/VALIDATION_MATRIX.json", "demo/run_validation.py"]
    files = [ROOT / name for name in names]
    for directory in ("engine", "skill", "tests", "demo/cases", "evaluation", "tools", ".github"):
        files.extend(p for p in (ROOT / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
    return sorted(set(files))


def source_fingerprint() -> str:
    digest = hashlib.sha256()
    for path in source_files():
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\x00" + path.read_bytes() + b"\x00")
    return digest.hexdigest()


def main() -> int:
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    _, skill_zip = build(ROOT / "artifacts/skillsentinel_build")
    source_zip = output / f"skillsentinel-{__version__}-source.zip"
    files = source_files()
    for path in files:
        raw = path.read_bytes()
        if re.search(rb"[A-Za-z]:[/\\]{1,2}Users[/\\]{1,2}[^/\\\r\n]+|\bses_[A-Za-z0-9]{20,}\b", raw):
            raise ValueError(f"Machine-specific data found in source: {path.relative_to(ROOT)}")
    with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            name = (Path("SkillSentinel") / path.relative_to(ROOT)).as_posix()
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    artifacts = [source_zip, skill_zip, *sorted(output.glob(f"skillsentinel-{__version__}-*.whl"))]
    manifest = {"version": __version__, "source_sha256": source_fingerprint(), "source_files": len(files),
                "artifacts": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}}
    (output / "release_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(source_zip)
    print(skill_zip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
