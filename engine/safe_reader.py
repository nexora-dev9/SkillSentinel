from __future__ import annotations

import json
import hashlib
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .models import AuditInput, LoadedFile, SkippedFile


MAX_FILES = 300
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".xml",
    ".csv",
    ".env",
}


class UnsafeInputError(ValueError):
    """Raised when an input violates a hard safety boundary."""


def _is_allowed_text_path(path: str) -> bool:
    name = Path(path).name.lower()
    return name in {"skill.md", ".env", "dockerfile", "license", "copying", "notice"} or name.startswith(".env.") or Path(name).suffix.lower() in TEXT_EXTENSIONS


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _snapshot(entries: list[dict]) -> dict:
    entries = sorted(entries, key=lambda item: item["path"])
    payload = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {"sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(), "manifest": entries}


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise UnsafeInputError("file grew beyond the per-file size limit during reading")
    return data


def _decode_text(data: bytes, path: str) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None


def _safe_archive_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"..", ""} for part in pure.parts):
        raise UnsafeInputError(f"ZIP contains unsafe path: {name!r}")
    if not pure.parts or any(":" in part or part.endswith((".", " ")) for part in pure.parts):
        raise UnsafeInputError(f"ZIP contains non-portable path: {name!r}")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if any(part.split(".")[0].lower() in reserved for part in pure.parts):
        raise UnsafeInputError(f"ZIP contains reserved device path: {name!r}")
    return str(pure)


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _read_zip(path: Path) -> AuditInput:
    files: list[LoadedFile] = []
    skipped: list[SkippedFile] = []
    total = 0
    manifest: list[dict] = []
    seen_names: set[str] = set()
    if path.stat().st_size > MAX_TOTAL_BYTES:
        raise UnsafeInputError("compressed ZIP exceeds the input size limit")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise UnsafeInputError(f"ZIP contains too many files: {len(infos)} > {MAX_FILES}")

            for info in infos:
                safe_name = _safe_archive_name(info.filename)
                canonical = safe_name.casefold()
                if canonical in seen_names:
                    raise UnsafeInputError("ZIP contains duplicate or case-colliding paths")
                seen_names.add(canonical)
                if info.is_dir():
                    continue
                if _zip_entry_is_symlink(info):
                    skipped.append(SkippedFile(safe_name, "symlink entry skipped", info.file_size))
                    manifest.append({"path": safe_name, "state": "symlink"})
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    skipped.append(SkippedFile(safe_name, "file exceeds per-file size limit", info.file_size))
                    manifest.append({"path": safe_name, "size": info.file_size, "state": "oversize"})
                    continue
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise UnsafeInputError(f"ZIP uncompressed size exceeds {MAX_TOTAL_BYTES} bytes")
                with archive.open(info) as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != info.file_size or len(data) > MAX_FILE_BYTES:
                    raise UnsafeInputError("ZIP entry size does not match bounded content")
                manifest.append({"path": safe_name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                if not _is_allowed_text_path(safe_name):
                    skipped.append(SkippedFile(safe_name, "unsupported file type", info.file_size))
                    continue
                text = _decode_text(data, safe_name)
                if text is None:
                    skipped.append(SkippedFile(safe_name, "binary or non-UTF text skipped", info.file_size))
                    continue
                files.append(LoadedFile(safe_name, text, info.file_size))
    except UnsafeInputError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError) as exc:
        raise UnsafeInputError(f"ZIP cannot be safely read: {exc.__class__.__name__}") from exc

    return AuditInput(
        input_type="skill_zip",
        source=str(path),
        files=files,
        skipped_files=skipped,
        metadata={"uncompressed_bytes_seen": total, **_snapshot(manifest)},
    )


def _read_directory(path: Path) -> AuditInput:
    files: list[LoadedFile] = []
    skipped: list[SkippedFile] = []
    total = 0
    seen = 0
    seen_directories = 0
    manifest: list[dict] = []

    for root, dirs, names in os.walk(path, followlinks=False):
        seen_directories += len(dirs)
        if seen_directories > MAX_FILES:
            raise UnsafeInputError("directory contains too many subdirectories")
        root_path = Path(root)
        for name in dirs[:]:
            candidate = root_path / name
            if is_link(candidate):
                rel = candidate.relative_to(path).as_posix()
                skipped.append(SkippedFile(rel, "symlink or reparse directory skipped"))
                manifest.append({"path": rel, "state": "link"})
                dirs.remove(name)
        for name in names:
            seen += 1
            if seen > MAX_FILES:
                raise UnsafeInputError(f"directory contains too many files: > {MAX_FILES}")
            file_path = root_path / name
            rel = file_path.relative_to(path).as_posix()
            try:
                if is_link(file_path):
                    skipped.append(SkippedFile(rel, "symlink skipped"))
                    manifest.append({"path": rel, "state": "link"})
                    continue
                info = file_path.stat()
                if not stat.S_ISREG(info.st_mode):
                    skipped.append(SkippedFile(rel, "non-regular file skipped"))
                    manifest.append({"path": rel, "state": "non-regular"})
                    continue
                size = info.st_size
            except OSError as exc:
                skipped.append(SkippedFile(rel, f"metadata read failed: {exc.__class__.__name__}"))
                manifest.append({"path": rel, "state": "metadata error"})
                continue
            if size > MAX_FILE_BYTES:
                skipped.append(SkippedFile(rel, "file exceeds per-file size limit", size))
                manifest.append({"path": rel, "size": size, "state": "oversize"})
                continue
            total += size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeInputError(f"directory size exceeds {MAX_TOTAL_BYTES} bytes")
            try:
                data = _read_bounded(file_path)
            except OSError as exc:
                skipped.append(SkippedFile(rel, f"file read failed: {exc.__class__.__name__}", size))
                manifest.append({"path": rel, "state": "read error"})
                continue
            manifest.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            total += len(data) - size
            if total > MAX_TOTAL_BYTES:
                raise UnsafeInputError("directory content grew beyond the total size limit")
            if not _is_allowed_text_path(rel):
                skipped.append(SkippedFile(rel, "unsupported file type", size))
                continue
            text = _decode_text(data, rel)
            if text is None:
                skipped.append(SkippedFile(rel, "binary or non-UTF text skipped", size))
                continue
            files.append(LoadedFile(rel, text, len(data)))

    return AuditInput(
        input_type="skill_directory",
        source=str(path),
        files=files,
        skipped_files=skipped,
        metadata={"bytes_seen": total, **_snapshot(manifest)},
    )


def _looks_like_mcp_json(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    keys = {str(key).lower() for key in data.keys()}
    return bool(keys & {"mcpservers", "mcp_servers", "servers"})


def _read_single_file(path: Path) -> AuditInput:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise UnsafeInputError(f"file exceeds per-file size limit: {size} > {MAX_FILE_BYTES}")
    if not _is_allowed_text_path(path.name):
        raise UnsafeInputError(f"unsupported input file type: {path.suffix or '<none>'}")
    data = _read_bounded(path)
    text = _decode_text(data, path.name)
    if text is None:
        raise UnsafeInputError("input is binary or is not supported UTF text")

    input_type = "skill_markdown" if path.name.lower() == "skill.md" else "text_file"
    metadata: dict[str, object] = {}
    if path.suffix.lower() == ".json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UnsafeInputError(f"invalid JSON: {exc.msg}") from exc
        if not _looks_like_mcp_json(parsed):
            raise UnsafeInputError("JSON input is not recognized as an MCP configuration")
        input_type = "mcp_json"
        metadata["top_level_keys"] = list(parsed.keys())[:50]

    metadata.update(_snapshot([{"path": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}]))
    return AuditInput(input_type, str(path), [LoadedFile(path.name, text, size)], [], metadata)


def load_input(source: str | Path) -> AuditInput:
    path = Path(source).expanduser().absolute()
    if not path.exists():
        raise FileNotFoundError(path)
    if is_link(path):
        raise UnsafeInputError("input root must not be a symlink or reparse point")
    path = path.resolve()
    if path.is_dir():
        return _read_directory(path)
    if path.suffix.lower() == ".zip":
        return _read_zip(path)
    return _read_single_file(path)
