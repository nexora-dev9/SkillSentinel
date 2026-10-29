from __future__ import annotations

import re
from dataclasses import dataclass

from .redaction import SECRET_PATTERN


@dataclass(frozen=True, slots=True)
class TextRule:
    rule_id: str
    severity: str
    category: str
    title: str
    pattern: re.Pattern[str]
    explanation: str
    suggested_action: str
    auto_fixable: bool = False
    semantic_review: bool = False


RULES: tuple[TextRule, ...] = (
    TextRule(
        "SEC001",
        "high",
        "secret",
        "Potential hard-coded secret or token",
        SECRET_PATTERN,
        "A credential-like value appears to be embedded in text or configuration.",
        "Remove the embedded value and load credentials from an approved secret mechanism.",
        semantic_review=True,
    ),
    TextRule(
        "SEC002", "high", "secret", "Potential embedded Bearer credential",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
        "An authorization-like value appears in the input.",
        "Use an approved credential mechanism and review whether the value is a placeholder or a real credential.",
        semantic_review=True,
    ),
    TextRule(
        "CAP001",
        "high",
        "process_execution",
        "Shell or process execution capability",
        re.compile(
            r"(?i)\b(subprocess\.(?:run|popen|call)|os\.system\s*\(|child_process\.(?:exec|spawn)|shell\s*=\s*true|powershell(?:\.exe)?\b|cmd\.exe\b)"
        ),
        "The Skill appears to declare or use local process execution capability.",
        "Review whether process execution is necessary and constrain it to explicit allow-listed operations.",
        semantic_review=True,
    ),
    TextRule(
        "NET001",
        "medium",
        "network",
        "External network endpoint referenced",
        re.compile(r"https?://[^\s)\]}>\"']+", re.IGNORECASE),
        "The Skill references an external network endpoint.",
        "Confirm the endpoint is required, expected, and documented; define failure behavior.",
        semantic_review=True,
    ),
    TextRule(
        "FS001",
        "high",
        "sensitive_path",
        "Sensitive local path referenced",
        re.compile(
            r"(?i)(?:~[/\\]\.ssh\b|\.aws[/\\]credentials\b|/etc/(?:passwd|shadow)\b|appdata[/\\].*(?:chrome|edge|firefox)|\.config[/\\])"
        ),
        "The Skill references a path commonly associated with credentials, browser profiles, or sensitive system data.",
        "Verify that this access is strictly required; otherwise remove it or narrow the file scope.",
        semantic_review=True,
    ),
    TextRule(
        "OUT001",
        "high",
        "data_egress",
        "Potential outbound data transfer",
        re.compile(
            r"(?i)\b(requests\.post\s*\(|httpx\.post\s*\(|axios\.post\s*\(|fetch\s*\([^\n]{0,200}method\s*:\s*[\"']POST[\"']|curl\b[^\n]{0,120}\s(?:-d|--data|--upload-file)\b)"
        ),
        "The Skill may send data to an external destination.",
        "Require an explicit destination, minimum necessary payload, and user confirmation before external transmission.",
        semantic_review=True,
    ),
    TextRule(
        "INS001",
        "medium",
        "instruction_integrity",
        "Suspicious instruction override language",
        re.compile(
            r"(?i)(\b(ignore (?:all |the )?(?:previous|prior) instructions|reveal (?:the )?system prompt|bypass (?:safety|policy)|disable (?:safety|guardrails?))\b|忽略.{0,8}(?:之前|此前|系统|安全).{0,8}(?:指令|规则)|绕过.{0,6}(?:安全|策略)|(?:泄露|输出).{0,6}系统提示词)"
        ),
        "Instruction text attempts to override prior instructions or bypass safeguards.",
        "Treat the instruction as untrusted content and require manual review.",
        semantic_review=True,
    ),
)


CONFIRMATION_TERMS = re.compile(
    r"(?i)(用户确认|人工确认|明确确认|确认后|征得.*确认|user confirmation|confirm before|explicit confirmation)"
)
FALLBACK_TERMS = re.compile(
    r"(?i)(降级|失败处理|失败时|不可用时|fallback|graceful|if .* unavailable|on failure)"
)
