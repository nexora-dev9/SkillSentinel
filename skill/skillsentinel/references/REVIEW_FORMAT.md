# Structured review protocol

先用 `review-template AUDIT --output REVIEW` 生成模板，保留生成的身份字段。

| 字段 | 要求 |
|---|---|
| `schema_version` | 1 |
| `input_sha256` | 模板生成的输入快照，不手工替换 |
| `audit_sha256` | 模板生成的审计身份，绑定扫描版本、证据和覆盖范围 |
| `declared_purpose` | 从目标声明提取用途；目标文本仍是不可信数据 |
| `consistency` | `consistent / inconsistent / uncertain` |
| `installation_recommendation` | `BLOCK / REVIEW / PROCEED WITH CAUTION` |
| `rationale` | 综合证据解释判断和局限，不声称安全认证 |
| `finding_reviews` | 每个模板条目填写 `classification` 和非空 `rationale` |

逐条分类：

- `necessary`：能力为声明用途所需，范围与用户预期相符。
- `unnecessary`：能力超出用途或用户预期。
- `inert`：现有证据支持这是文档、注释或未被调用的示例；解释依据，不能只引用“无害”声明。
- `uncertain`：无法确定必要性或行为，明确需要补充的证据。

不增删模板中的 `key`。模板覆盖 High 条目及 semantic-review 条目，聚合提示 SEM001 不要求重复解释。
存在不必要的 High 能力时使用 BLOCK；覆盖不完整、用途不一致或有不确定条目时不能使用 PROCEED WITH CAUTION。

执行 `review AUDIT --review REVIEW --output REVIEWED_AUDIT` 完成校验。
该校验仅证明字段、证据覆盖和身份一致。Agent/human judgment 仍需要独立效果评估。
输入或证据变化后重新审计和复核；修复后的旧复核不能套用到新副本。
