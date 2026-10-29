# SkillSentinel · 智链卫士

**非执行式 Skill/MCP 安装前审计、证据绑定复核与保守副本修复。**

[English](README.md) | **简体中文**

面向准备引入第三方 Agent Skill 或 MCP 的个人和团队。读取文件并定位风险，由 Agent 或人工判断用途与能力是否一致，经确认后补齐副本中的规范与测试骨架，再交付可复验的报告。

Python 3.10+ · 无运行时第三方依赖 · MIT

## 能做什么

- 输入：`SKILL.md`、本地 Skill 文件夹、Skill ZIP、MCP JSON。
- 静态证据：凭据、进程调用、网络目标、潜在外发、敏感路径、指令覆盖、结构和质量问题。
- Python 证据区分代码调用、字符串、注释，识别常见导入别名和跨行调用；其他语言使用文本规则。
- 内容指纹绑定审计、逐条语义复核、已确认计划、修复副本和报告。
- 生成离线 HTML 报告、脱敏 Diff、修复 ZIP、修复前后审计 JSON。
- 修复只补文档和草稿测试；保留未解决的能力风险和人工复核项。

扫描不执行目标，也不连接 MCP endpoint，不安装目标依赖。结论是预审建议，不能证明安全。完整边界见 [SECURITY.md](SECURITY.md)。

## 安装独立命令行工具

在仓库根目录执行：

```text
python -m pip install .
skillsentinel --version
```

也可从源码运行以下所有命令：将 `skillsentinel` 替换为 `python -m engine.cli`。

## 安装 DuMate Skill

```text
python skill/build_skill.py
```

在 DuMate 的技能安装入口导入 `artifacts/skillsentinel_build/skillsentinel.zip`。
这个 ZIP 自带同一份引擎和许可证，仅需要 Python 3.10+。
`skill/skillsentinel/` 是构建模板；请安装生成后的完整 ZIP，不要直接安装缺少引擎副本的模板目录。

建议触发语：“检查这个 Skill 是否适合安装”“审计这个 MCP 配置”。
模型判断、确认交互和最终解释由宿主 Agent 完成；引擎不依赖特定模型服务。

## 快速体验：审计、计划、确认、修复、报告

所有输出写到目标之外的新目录；同名结果不会被覆盖。

```text
skillsentinel audit demo/cases/04_auto_repairable --output out/audit.json
skillsentinel plan demo/cases/04_auto_repairable --output out/patch_plan.json
```

查看计划内容后，确认仅补齐文档约束与草稿测试，再执行：

```text
skillsentinel repair demo/cases/04_auto_repairable --plan out/patch_plan.json --output-dir out/repair --confirm
skillsentinel report out/audit.json --repair-report out/repair/repair_report.json --output out/report.html
```

修复结果包含 `before_audit.json`、`after_audit.json`、`repair_report.json`、`repair.diff`、`patched_skill/` 和 `patched_skill.zip`。
原件哈希必须保持一致；输入、计划或复制内容变化时修复失败。`--confirm` 是调用者声明已取得用户确认，CLI 不能证明用户真的看过计划。

生成的 `tests/cases.json` 标记为 `requires_manual_validation: true`，复扫保留 `TST004`。
补骨架不会被当作测试成功，也不会宣称外发或执行风险已修复。

## 结构化语义复核

```text
skillsentinel review-template out/audit.json --output out/review.json
```

由 Agent 或人工填写模板：声明用途、用途一致性、安装建议、每条必需证据的分类和解释。
分类为 `necessary / unnecessary / inert / uncertain`；安装建议为 `BLOCK / REVIEW / PROCEED WITH CAUTION`。
填写说明见 [复核协议](skill/skillsentinel/references/REVIEW_FORMAT.md)。

```text
skillsentinel review out/audit.json --review out/review.json --output out/reviewed_audit.json
skillsentinel report out/reviewed_audit.json --output out/reviewed_report.html
```

校验会拒绝快照不一致、遗漏证据、重复条目，以及与风险政策冲突的建议。
校验保证结构与证据绑定，不保证语义判断正确。未经复核的报告明确显示 `unreviewed`；旧格式 Agent 结果不会被当作已校验判断。

## CLI 与返回码

`audit`、`plan`、`repair`、`review-template`、`review`、`report` 支持 `--help`。

```text
skillsentinel audit path/to/skill --fail-on high --output out/ci_audit.json
```

- `0`：命令完成；不代表输入安全。
- `1`：`audit --fail-on` 达到指定静态严重度门槛。
- `2`：参数、输入、确认、复核、计划或输出错误。

自动修复仅支持一个明确 Skill 根的本地目录。ZIP、单文档和 MCP 输入为 audit-only。
读取上限：300 个文件/ZIP 条目、单文件 2 MiB、累计 20 MiB。跳过内容明确记录；目录链接与 Windows junction 不遍历。

## 开发与验证

```text
python -m unittest discover -s tests -v
python demo/run_validation.py --output-dir out/demo_validation
python tools/evaluate_pairs.py --output-dir out/paired_evaluation
python tools/build_release.py
```

测试覆盖脱敏、证据来源、输入边界、复核协议、确认门槛、快照变化、格式保留、原件保护、CLI 和独立 Skill ZIP。
成对样例包含静态预期与人工语义标签。评估脚本只统计已实际执行的项目；未提供 Agent 复核结果时，不输出模型准确率。
GitHub CI 配置包含 Windows/Linux 和 Python 版本矩阵；本地验证结果不等同于远端 CI 已运行。

发布脚本生成完整 Skill ZIP、可直接作为 GitHub 仓库内容的源码 ZIP、SHA-256 清单。
源码包排除机器记录、历史交付物、比赛 PDF、截图和真实凭据。

## 项目结构

```text
engine/                标准库审计、复核、修复、报告与 CLI
skill/skillsentinel/   Skill 模板、决策政策和复核协议
skill/build_skill.py   将同一份引擎打包为独立 Skill
tests/                 非执行式回归和集成测试
demo/                  六类人工无害样例
evaluation/            成对样例与语义标注
tools/                 评估、验证记录和发布工具
docs/                  本地比赛材料；不包含在发布源码包
```

详见 [贡献指南](CONTRIBUTING.md)、[更新记录](CHANGELOG.md)。所有演示凭据均为人工测试值，未知目标脚本不会被执行。
