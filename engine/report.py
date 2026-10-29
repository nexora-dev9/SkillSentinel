"""A portable, escaped HTML report for any saved audit."""
from __future__ import annotations

import html

from .redaction import redact_data
from .review import attach_review


def render_report(audit: dict, repair: dict | None = None) -> str:
    audit = redact_data(audit)
    semantic = audit.get("semantic_review")
    if semantic and semantic.get("schema_version") == 1:
        audit = attach_review(audit, semantic)
        decision = audit["decision"]
    else:
        decision = {"status": "static_only", "consistency": "unreviewed", "installation_recommendation": "REVIEW",
                    "rationale": "语义复核未完成或旧格式结果尚未校验；以下为静态证据。"}
        if not semantic:
            decision.update(audit.get("decision", {}))
            decision["consistency"] = "unreviewed"
            decision["status"] = "static_only"
    esc = lambda value: html.escape(str(value), quote=True)
    reviews = {item["key"]: item for item in (audit.get("semantic_review", {}).get("finding_reviews") or [])}
    rows = []
    for finding in audit.get("findings", []):
        evidence = "<br>".join(
            f"{esc(ev.get('path', ''))}{esc(ev.get('pointer') or (':' + str(ev['line']) if ev.get('line') else ''))} [{esc(ev.get('origin', 'unknown'))}]<br><code>{esc(ev.get('snippet', ''))}</code>"
            for ev in finding.get("evidence", [])
        ) or "结构检查"
        judgment = reviews.get(finding.get("key"), {})
        rows.append(f"<tr><td>{esc(finding['severity'])}</td><td>{esc(finding['id'])}<br>{esc(finding['title'])}</td>"
                    f"<td>{evidence}</td><td>{esc(judgment.get('classification', '未复核'))}<br>{esc(judgment.get('rationale', ''))}</td>"
                    f"<td>{esc(finding['suggested_action'])}<br>规范补齐候选：{'是' if finding.get('auto_fixable') else '否'}</td></tr>")
    skipped = "".join(f"<li>{esc(f['path'])}：{esc(f['reason'])}</li>" for f in audit.get("input", {}).get("skipped_files", [])) or "<li>没有记录跳过文件；单文档审计仍只覆盖该文档。</li>"
    repair_html = ""
    if repair:
        repair = redact_data(repair)
        snapshot = audit.get("input", {}).get("sha256")
        if not snapshot or repair.get("source_sha256") != snapshot:
            raise ValueError("Repair report does not match this audit snapshot.")
        repair_html = f"<section><h2>修复副本</h2><p>Findings：{esc(repair['before']['findings'])} → {esc(repair['after']['findings'])}。"
        repair_html += f"补齐规范：{esc(' / '.join(repair.get('resolved_quality_findings', [])))}；运行时代码风险消除：0。</p>"
        repair_html += f"<p>剩余条目：{esc(' / '.join(repair.get('remaining_findings', [])))}。生成测试是待补充的骨架。</p></section>"
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SkillSentinel 审计报告</title><style>
body{{font-family:system-ui,'Microsoft YaHei',sans-serif;margin:0;background:#f5f7fb;color:#18253b;line-height:1.6}}
main{{max-width:1200px;margin:auto;padding:28px}}section{{background:white;padding:22px;margin:18px 0;border-radius:12px}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:12px;border-bottom:1px solid #ddd;vertical-align:top;overflow-wrap:anywhere}}
code{{white-space:pre-wrap;font-size:12px}}h1{{color:#315efb}}.decision{{font-size:22px;font-weight:700}}small{{overflow-wrap:anywhere}}
@media(max-width:700px){{main{{padding:12px}}table{{display:block;overflow-x:auto}}}}
</style></head><body><main><h1>智链卫士 SkillSentinel</h1>
<section><div class="decision">{esc(decision['installation_recommendation'])}</div><p>复核状态：{esc(decision['status'])}；用途一致性：{esc(decision['consistency'])}</p><p>{esc(decision.get('rationale', ''))}</p>
<small>输入：{esc(audit.get('input', {}).get('source', ''))}<br>快照 SHA-256：{esc(audit.get('input', {}).get('sha256', '旧结果无指纹'))}</small></section>
<section><h2>证据与建议（{len(audit.get('findings', []))} 项）</h2><table><thead><tr><th>严重度</th><th>条目</th><th>证据来源</th><th>语义判断</th><th>建议</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<section><h2>覆盖范围</h2><p>完整读取：{esc(audit.get('coverage', {}).get('complete', False))}</p><ul>{skipped}</ul></section>
{repair_html}<section><h2>判断边界</h2><p>本报告是安装前预审，不是安全认证。代码调用、字符串和注释的分类不证明运行时可达性。未知目标脚本从未执行，语义结果来自复核者。</p></section>
</main></body></html>"""
