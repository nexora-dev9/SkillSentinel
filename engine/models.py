from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:
    path: str
    line: int | None
    snippet: str
    origin: str = "unknown"
    pointer: str | None = None


@dataclass(slots=True)
class Finding:
    id: str
    severity: str
    category: str
    title: str
    explanation: str
    auto_fixable: bool
    suggested_action: str
    evidence: list[Evidence] = field(default_factory=list)
    semantic_review: bool = False
    key: str = ""


@dataclass(slots=True)
class LoadedFile:
    path: str
    text: str
    size: int


@dataclass(slots=True)
class SkippedFile:
    path: str
    reason: str
    size: int | None = None


@dataclass(slots=True)
class AuditInput:
    input_type: str
    source: str
    files: list[LoadedFile] = field(default_factory=list)
    skipped_files: list[SkippedFile] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def to_dict(value: Any) -> Any:
    return asdict(value)
