"""报告导出（对应架构板块 6）：Markdown / JSON / CSV。"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .agent import Explainer
from .models import Finding

LEVEL_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_level = {level: 0 for level in LEVEL_RANK}
    by_type: dict[str, int] = {}
    for finding in findings:
        by_level[finding.level] = by_level.get(finding.level, 0) + 1
        by_type[finding.ftype.value] = by_type.get(finding.ftype.value, 0) + 1
    return {"total": len(findings), "by_level": by_level, "by_type": by_type}


def render_markdown(result: dict[str, Any]) -> str:
    findings: list[Finding] = result["findings"]
    stats = summarize(findings)
    lines: list[str] = []
    lines.append("# 网站安全智能巡检报告")
    lines.append("")
    lines.append("| 项目 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 巡检资产 | {result['asset']} |")
    lines.append(f"| 授权编号 | {result['authorization']} |")
    lines.append(f"| 完成时间 | {result['finished_at']} |")
    lines.append(f"| 发现页面 | {len(result['pages'])} 个 |")
    lines.append(f"| 请求总数 | {result['request_count']} 次（含被拦截的拒绝记录） |")
    lines.append(f"| 原始命中 → 去重后 | {result['raw_count']} → {stats['total']} 条 |")
    lines.append(f"| 二次验证后排除 | {result.get('excluded_false_positives', 0)} 条未复现项 |")
    lines.append("")
    lines.append("## 一、风险概览")
    lines.append("")
    lines.append("| 等级 | 数量 |")
    lines.append("| --- | --- |")
    for level in ("P0", "P1", "P2", "P3"):
        lines.append(f"| {level} | {stats['by_level'].get(level, 0)} |")
    lines.append("")
    lines.append("风险类型分布：" + ("、".join(f"{k} {v}" for k, v in stats["by_type"].items()) or "无"))
    lines.append("")
    lines.append("## 二、风险明细")
    lines.append("")
    if not findings:
        lines.append("本周期未发现风险。")
        lines.append("")
    for index, finding in enumerate(findings, 1):
        lines.append(f"### {index}. [{finding.level}] {finding.title}")
        lines.append("")
        lines.append(f"- 风险类型：{finding.ftype.value}　规则：`{finding.rule_id}`")
        lines.append(f"- 位置：{finding.url}　（{finding.location}）")
        lines.append(f"- 发现工具：{', '.join(finding.sources) or finding.tool}"
                     f"　档位：{finding.tier.value}")
        lines.append(f"- 风险分：{finding.risk_score}（置信度 {finding.confidence}，"
                     f"状态 {finding.status.value}，二次确证：{'是' if finding.verified else '否'}）")
        if finding.cwe:
            reference = Explainer.reference(finding)
            lines.append(f"- 弱点分类：{finding.cwe}　{reference}")
        lines.append("- 证据：")
        for evidence in finding.evidence:
            lines.append(f"  - ({evidence.kind}) {evidence.summary}")
        lines.append(f"- 影响：{finding.impact}")
        lines.append(f"- 修复建议：{finding.remediation}")
        lines.append("")
    lines.append("## 三、智能体执行说明（可解释性）")
    lines.append("")
    lines.append("规划的子任务与选择理由：")
    lines.append("")
    for subtask in result["plan"].subtasks:
        lines.append(f"- [{subtask.tier.value}] {subtask.capability}（{subtask.target}）："
                     f"{subtask.reason}")
    lines.append("")
    blocked = [entry for entry in result["trace"] if entry["status"] == "blocked"]
    errored = [entry for entry in result["trace"] if entry["status"] == "error"]
    lines.append(f"工具执行留痕：共 {len(result['trace'])} 次调用，"
                 f"其中被合规拦截 {len(blocked)} 次、执行异常 {len(errored)} 次。")
    lines.append("")
    lines.append("## 四、基线对比与生命周期")
    lines.append("")
    changes = result["changes"]
    lines.append(f"- 新增风险：{len(changes['new'])} 条")
    lines.append(f"- 仍然存在（复现）：{len(changes['reopened'])} 条")
    lines.append(f"- 本周期已消失（疑似修复）：{len(changes['fixed'])} 条")
    lines.append("")
    lines.append("## 五、合规审计摘要")
    lines.append("")
    rejected = result["audit"].rejected()
    lines.append(f"- 出站请求：{result['request_count']} 次（全部经授权闸门校验并记录）")
    lines.append(f"- 被拒绝的请求：{len(rejected)} 次")
    for entry in rejected[:10]:
        lines.append(f"  - {entry.ts} {entry.action} {entry.target} → {entry.detail}")
    lines.append("")
    lines.append("## 六、说明")
    lines.append("")
    lines.append("- 本报告由智能巡检智能体生成；所有结论均可回溯到证据与来源工具。")
    lines.append("- 默认仅执行被动档（T0）与受控探测档（T1）；主动验证档（T2）默认关闭。")
    lines.append("- 证据中的敏感值已按策略脱敏，原始值单独加密存储。")
    return "\n".join(lines)


def render_json(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset": result["asset"],
        "authorization": result["authorization"],
        "finished_at": result["finished_at"],
        "request_count": result["request_count"],
        "raw_count": result["raw_count"],
        "summary": summarize(result["findings"]),
        "changes": result["changes"],
        "plan": [subtask.__dict__ | {"tier": subtask.tier.value} for subtask in result["plan"].subtasks],
        "trace": result["trace"],
        "findings": [finding.to_dict() for finding in result["findings"]],
    }


def write_outputs(result: dict[str, Any], out_dir: str | Path, name: str = "report") -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / f"{name}.md"
    json_path = out / f"{name}.json"
    csv_path = out / f"{name}.csv"
    md_path.write_text(render_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(render_json(result), ensure_ascii=False, indent=2),
                         encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["等级", "风险分", "类型", "标题", "URL", "位置", "规则", "来源工具",
                         "置信度", "二次确证", "状态", "影响", "修复建议"])
        for finding in result["findings"]:
            writer.writerow([finding.level, finding.risk_score, finding.ftype.value,
                             finding.title, finding.url, finding.location, finding.rule_id,
                             "/".join(finding.sources), finding.confidence,
                             "是" if finding.verified else "否", finding.status.value,
                             finding.impact, finding.remediation])
    return {"markdown": md_path, "json": json_path, "csv": csv_path}
