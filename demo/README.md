# Phase 5 Demo / Validation Set

本目录只包含**人工构造、无真实恶意行为**的 Skill/MCP 样例，用于稳定验证 SkillSentinel 的比赛演示链路。

## 六类固定场景

1. `01_safe_local_summary`：正常安全、本地只读 Skill。
2. `02_static_risk`：明显静态风险证据，但全部为惰性文本。
3. `03_purpose_mismatch`：声明“仅本地整理”，却出现敏感路径与外发能力样式，用于 DuMate 做用途—能力一致性复核。
4. `04_auto_repairable`：同时存在可确定性补齐的 tests / confirmation / fallback，作为主 Demo 修复闭环样例。
5. `05_manual_only`：只保留必须人工判断的高风险/语义项，不应自动修改。
6. `06_mcp_config`：MCP JSON，本地进程 + 虚构测试 Token。

所有 `scripts/` 文件均只包含字符串常量，不允许作为 Demo 执行。主 Demo 优先使用 `04_auto_repairable`，展示：

**发现 → 证据 → 解释 → Patch Plan → 用户确认 → 修复副本 → 复扫 → 报告交付**

期望结果详见 `VALIDATION_MATRIX.json`。
