from __future__ import annotations

import shutil
import zipfile
import json
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "skill" / "skillsentinel"
ENGINE = ROOT / "engine"
DEFAULT_OUTPUT = ROOT / "artifacts" / "skillsentinel_build"

ENGINE_FILES = (
    "__init__.py",
    "models.py",
    "safe_reader.py",
    "rules.py",
    "scanner.py",
    "repair.py",
    "redaction.py",
    "review.py",
    "report.py",
    "cli.py",
)


def build(output_root: Path = DEFAULT_OUTPUT) -> tuple[Path, Path]:
    output_root = output_root.resolve()
    if output_root == ROOT or output_root.is_relative_to(TEMPLATE) or output_root.is_relative_to(ENGINE):
        raise ValueError("Build output must not replace project sources")
    output_root.mkdir(parents=True, exist_ok=True)
    package = output_root / "skillsentinel"
    if package.exists():
        if not (package / "scripts" / "skillsentinel_engine" / "__init__.py").is_file():
            raise ValueError("Refusing to replace an unrecognized package directory")
        shutil.rmtree(package)
    shutil.copytree(TEMPLATE, package, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    bundled_engine = package / "scripts" / "skillsentinel_engine"
    bundled_engine.mkdir(parents=True, exist_ok=True)
    for name in ENGINE_FILES:
        shutil.copy2(ENGINE / name, bundled_engine / name)
    shutil.copy2(ROOT / "LICENSE", package / "LICENSE")

    zip_path = output_root / "skillsentinel.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file_path in sorted(package.rglob("*")):
            if file_path.is_dir():
                continue
            relative = file_path.relative_to(output_root)
            info = zipfile.ZipInfo(relative.as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, file_path.read_bytes())
    manifest = {file.relative_to(output_root).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
                for file in sorted(package.rglob("*")) if file.is_file()}
    manifest[zip_path.name] = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    (output_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return package, zip_path


if __name__ == "__main__":
    package, zip_path = build()
    print(package)
    print(zip_path)
