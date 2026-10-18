# coding=utf-8
"""⑧ 代码节点 · 报告生成与告警。

输入：
    findings_payload   ⑥ 去重验证分级的 result_key（含 findings 与 stats）
    explain_payload    ⑦ 模型节点的输出（JSON 数组：id/impact/remediation/cwe_name）
    discover_payload   ④ 资产发现的 result_key（可选，用于页面数与合规拦截统计）

输出（result_key，JSON 字符串）：
    {
      "summary": "...",
      "report": {"markdown": "...", "html": "..."},
      "alert":  {"triggered","level","channel","sent","payload"},
      "stats":  {"findings","pages","blocked","by_level"}
    }

设计要点：
    1. 报告为确定性模板渲染——模型只负责"影响与建议"的文字，格式不依赖模型；
    2. 模型输出做容错解析：自动剥离 ```json 代码块、从长文本里抠出 JSON 数组；
    3. 告警分级触发：仅 P0/P1 即时推送，其余进报告；未配置通道时只组装不发送；
    4. 只读：告警是唯一出站请求，且只发往配置的 Webhook。
"""

from runtime import Args

import base64
import csv
import io
import json
import re
import time
import urllib.request

# ------------------------- 可调参数 -------------------------
ALERT_WEBHOOK = ""             # 留空 = 只组装不发送；填 https://webhook.site/xxx 之类可实测推送
ALERT_MIN_LEVELS = ("P0", "P1")  # 触发即时告警的最低等级
REPORT_TITLE = "网站安全智能巡检报告"
USER_AGENT = "SecurityInspector/1.0 (+authorized-scan)"

# ---- 内置模型调用（不依赖上游模型节点，⑦ 空转时自动兜底）----
LLM_ENABLED = True             # 关掉就只用内置模板，不发模型请求
LLM_MODEL = "HengNao-v4"
LLM_MAX_TOKENS = 4096
LLM_BATCH = 12                 # 单次最多让模型解释多少条（按风险分从高到低取）
LLM_SYSTEM_PROMPT = """你是政企网站安全巡检报告的"风险解释与整改建议"专家，读者是网站运维与开发人员。
铁律：
1. 只依据输入证据推理，禁止虚构证据、禁止扩大影响面、禁止编造 CVE 编号；
2. 整改建议必须可执行：说清改哪个组件、加什么配置、怎么验证；
3. 证据不足时 impact 直接写"证据不足，建议人工复核"，不要硬猜；
4. 只输出 JSON 数组，不要任何解释文字，不要用 markdown 代码块包裹。"""
# -----------------------------------------------------------

DEFAULT_REMEDIATION = {
    "leak": "下线或脱敏该内容、补充访问控制，并排查同类页面与模板；安全：复采验证已不可访问。",
    "misconfig": "运维：在 Web 服务器/CDN 补齐对应安全响应头；安全：复采响应头确认已生效。",
    "vuln": "运维：屏蔽该路径的公开访问并清理文件；开发：把备份/配置产物移出站点目录。",
    "malware": "隔离并人工审计该段脚本，确认后清理，并排查文件写入与发布流程。",
    "tamper": "核对发布流程确认变更来源；非授权变更立即回滚并排查入侵路径。",
}

# ---- 报告导出：四种格式一次产出，落地方式按平台能力三级退化 ----
# 只有小文件内嵌成可点击链接（CSV/JSON）；HTML/Markdown 体积大，靠文件桶下载，
# 否则几段 base64 会把对话消息撑得很长，反而不便阅读。
EMBED_DATA_URI_FORMATS = ("csv", "json")
DATA_URI_MAX_CHARS = 20000     # data URI 超过这个长度就不内嵌
EXPORT_MIME = {"html": "text/html", "csv": "text/csv;charset=utf-8",
               "markdown": "text/markdown;charset=utf-8", "json": "application/json"}
# -------------------------------------------------------------


# ------------------------------ 工具函数 ------------------------------

def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def _load(raw, default=None):
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return default if default is not None else {}
    return raw if raw is not None else (default if default is not None else {})


def _unwrap(raw, default=None):
    """剥掉平台"引用"上游输出时包的 {"result_key": <内层 JSON>} 外壳（最多 4 层）。"""

    payload = _load(raw, None)
    for _ in range(4):
        if isinstance(payload, dict) and "result_key" in payload:
            inner = _load(payload["result_key"], None)
            if isinstance(inner, (dict, list)):
                payload = inner
                continue
        break
    return payload if payload is not None else (default if default is not None else {})


# ------------------------------ 证据纠偏 ------------------------------
# 证据里的域名只能来自实测结果。模型在写"影响/修复建议"时偶尔会把域名抄错一个字母
# （例如 fangxiangji.gymjilv.cn 写成 fangxiangji.bymjilv.cn），报告里出现不存在的域名，
# 整条证据链就不可信了。这里只纠正"与实测域名编辑距离 <= 2 的近似串"，其余 URL 原样保留。
URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")


def _host_of(value):
    """从 url / asset / 裸主机名里取出 host:port，取不到返回空串。"""

    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"(?i)^https?://([^/?#\s]+)", text)
    if match:
        return match.group(1).rstrip("/").lower()
    if re.match(r"^[A-Za-z0-9._-]+(:\d+)?$", text) and "." in text:
        return text.lower()
    return ""


def _edit_distance(left, right, cap):
    """带提前退出的小编辑距离：超过 cap 直接返回 cap+1。"""

    if abs(len(left) - len(right)) > cap:
        return cap + 1
    previous = list(range(len(right) + 1))
    for row, char_left in enumerate(left, 1):
        current = [row]
        for column, char_right in enumerate(right, 1):
            current.append(min(previous[column] + 1, current[column - 1] + 1,
                               previous[column - 1] + (char_left != char_right)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _observed_hosts(findings, discover):
    """本轮实测到的主机集合：风险条目的 url/asset/affected_urls + 已发现页面。"""

    hosts = set()
    for item in findings:
        values = [item.get("url"), item.get("asset")] + list(item.get("affected_urls") or [])
        for value in values:
            host = _host_of(value)
            if host:
                hosts.add(host)
    for page in (discover.get("pages") or []):
        host = _host_of(page.get("url") if isinstance(page, dict) else page)
        if host:
            hosts.add(host)
    return hosts


def _guard_urls(text, hosts, limit=2):
    """把被抄错的域名纠正回实测域名，返回 (纠正后的文本, 纠正处数)。"""

    if not text or not hosts:
        return text, 0
    counter = {"fixed": 0}

    def _replace(match):
        url = match.group(0)
        tail = ""
        while url and url[-1] in ")]}>,.;:!?":
            tail = url[-1] + tail
            url = url[:-1]
        host = _host_of(url)
        if not host or host in hosts:
            return match.group(0)
        for known in hosts:
            if _edit_distance(host, known, limit) <= limit:
                counter["fixed"] += 1
                return url.replace(host, known, 1) + tail
        return match.group(0)

    return URL_PATTERN.sub(_replace, text), counter["fixed"]


def _parse_explanations(raw):
    """容错解析模型输出：剥 ```json 代码块、从长文本里抠出 JSON 数组。"""

    data = _unwrap(raw, None)
    if isinstance(data, list):
        return data
    # 依次尝试：原始文本 → 剥壳后的内层字符串（平台引用会包一层 result_key）
    candidates = []
    if isinstance(raw, str):
        candidates.append(raw)
    inner = _load(raw, None)
    if isinstance(inner, dict) and isinstance(inner.get("result_key"), str):
        candidates.append(inner["result_key"])
    for text in candidates:
        cleaned = re.sub(r"```(?:json)?", "", str(text)).strip()
        start, end = cleaned.find("["), cleaned.rfind("]")
        if start < 0 or end <= start:
            continue
        try:
            parsed = json.loads(cleaned[start:end + 1])
        except Exception:
            continue
        if isinstance(parsed, list):
            return parsed
    return []


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ------------------------------ 模型调用 ------------------------------

def _ask_model(findings):
    """在代码节点内直接调用 HengNao-v4 生成影响与修复建议。

    这样即使上游模型节点（⑦）没配好，报告里的"影响/修复建议"依然是模型生成的。
    调用失败不抛异常，返回空列表，由内置模板兜底。
    """

    if not findings:
        return []
    brief = [{"id": f.get("id"), "type": f.get("type"), "rule_id": f.get("rule_id"),
              "title": f.get("title"), "severity": f.get("severity"),
              "level": f.get("level"), "url": f.get("url"),
              "occurrences": f.get("occurrences"),
              "evidence": (f.get("evidence") or [])[:2]} for f in findings[:LLM_BATCH]]
    user_content = ("以下是本轮巡检的风险清单（JSON 数组）：\n%s\n\n"
                    "请为每一条输出：impact（影响，不超过 80 字，写清谁能利用、需要什么前置条件、"
                    "造成什么后果）、remediation（分角色给出 1~2 条可执行整改项，每条附验证方法）、"
                    "cwe_name（CWE 的中文含义，可留空）。\n"
                    "严格按此格式输出 JSON 数组，id 必须与输入一致：\n"
                    '[{"id":"F-001","impact":"...","remediation":"...","cwe_name":"..."}]'
                    % json.dumps(brief, ensure_ascii=False))
    try:
        from openai import OpenAI

        client = OpenAI()
        response = client.chat.completions.create(
            model=LLM_MODEL, temperature=0.2, max_tokens=LLM_MAX_TOKENS, top_p=1,
            messages=[{"role": "system", "content": LLM_SYSTEM_PROMPT},
                      {"role": "user", "content": user_content}])
        text = response.choices[0].message.content or ""
        parsed = _parse_explanations(text)
        print("[报告与告警] 模型解释完成：请求 %d 条，返回 %d 条" % (len(brief), len(parsed)))
        return parsed
    except Exception as exc:
        print("[报告与告警] 模型调用失败，改用内置模板：%s" % exc)
        return []


# ------------------------------ 报告渲染 ------------------------------

def _task_stamp():
    """报告文件名用的时间戳；平台若注入了 task_id 就优先用它，保证同一任务文件名稳定。"""

    injected = globals().get("task_id")
    return str(injected) if injected else time.strftime("%Y%m%d-%H%M%S")


def _render_csv(findings, explain_map, suppressed):
    """明细表 CSV。带 UTF-8 BOM，Excel 双击打开中文不乱码——政企场景最常用的一种交付。"""

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(["编号", "等级", "类型", "标题", "规则ID", "风险分", "置信度", "状态",
                     "资产", "位置", "影响页面数", "检测来源", "工具", "影响说明", "整改建议",
                     "是否抑制"])
    for item in list(findings) + list(suppressed):
        explain = explain_map.get(item.get("id"), {}) or {}
        tools = "、".join(item.get("tools") or ([item.get("tool")] if item.get("tool") else []))
        writer.writerow([
            item.get("id", ""), item.get("level", ""), item.get("type", ""), item.get("title", ""),
            item.get("rule_id", ""), item.get("risk_score", ""), item.get("confidence", ""),
            item.get("status", ""), item.get("asset", ""), item.get("url", ""),
            item.get("occurrences", 1),
            {"tool": "工具线", "both": "两线交叉印证"}.get(item.get("source_line"), "被动检测线"),
            tools,
            explain.get("impact") or "证据不足，建议人工复核",
            explain.get("remediation") or DEFAULT_REMEDIATION.get(item.get("type", ""), ""),
            "是" if str(item.get("status")) == "suppressed" else "否",
        ])
    return "\ufeff" + buffer.getvalue()


def _data_uri(text, mime):
    return "data:%s;base64,%s" % (mime, base64.b64encode(text.encode("utf-8")).decode("ascii"))


def _save_exports(exports):
    """优先用平台的文件能力落盘；平台没有就返回空字典，由文本内交付兜底。

    exports: {格式: (文件名, 内容, mime)}
    """

    saved = {}
    try:
        bucket = FileBucket()                      # 平台注入的文件桶，本地/无此能力时抛异常
    except Exception as exc:
        print("[报告与告警] 平台未提供文件桶，改用文本内交付（data URI / 直接复制）：%s" % exc)
        return saved
    for name, (filename, content, _mime) in exports.items():
        try:
            path = bucket.save(filename, content.encode("utf-8"))
            saved[name] = str(path or filename)
        except Exception as exc:
            print("[报告与告警] %s 保存失败：%s" % (filename, exc))
    return saved


def _render_delivery(exports, saved, embed_formats=EMBED_DATA_URI_FORMATS):
    """生成"报告交付"区块：文件名、大小、三种获取方式，任一条通路可用即可下载。"""

    lines = ["", "—— 报告交付 ——"]
    links = []
    for name in ("html", "csv", "markdown", "json"):
        filename, content, mime = exports[name]
        size = len(content.encode("utf-8")) / 1024.0
        where = saved.get(name)
        lines.append("- %-9s %s（%.1f KB）%s"
                     % (name.upper(), filename, size, "→ 已落盘：%s" % where if where else ""))
        if name in embed_formats:
            uri = _data_uri(content, mime)
            if len(uri) <= DATA_URI_MAX_CHARS:
                links.append("[下载 %s](%s)" % (filename, uri))
    if links:
        lines.append("")
        lines.append("点此下载：" + " ｜ ".join(links))
    lines.append("")
    lines.append("获取方式：① 运行结果面板的文件页签（平台支持文件输出时）；"
                 "② 上面的下载链接（小体积的 CSV/JSON 已内嵌为可点击链接）；"
                 "③ 直接复制正文另存为 .md。")
    lines.append("HTML 报告为自包含单文件（样式内联、无外部依赖），可用浏览器打开后"
                 "「打印 → 另存为 PDF」得到 PDF 版；CSV 带 UTF-8 BOM，Excel 双击即开。")
    return "\n".join(lines), len(links)


def _render_targets(discover, findings):
    """授权目标采集情况：哪个目标采到几页、哪个目标一个页面都没采到、原因是什么。

    填了多个授权目标时，最怕"其中一个静默失败"——报告里只看得到成功那个的结果，
    很容易被当成"这个地址没问题"。这里把每个目标的结果都摊开。
    """

    seeds = ((discover.get("stats") or {}).get("seed_urls") or [])
    if not seeds:
        return "", 0
    errors = discover.get("errors") or []
    reason_by_url = {}
    for item in errors:
        if isinstance(item, dict):
            reason_by_url[str(item.get("url") or "")] = str(item.get("error") or "")
    pages = discover.get("pages") or []

    lines = ["", "## 授权目标采集情况", "", "| 授权目标 | 采集页面 | 结果 |", "| --- | --- | --- |"]
    failed = 0
    for seed in seeds:
        host = re.sub(r"(?i)^https?://", "", str(seed)).split("/")[0]
        count = sum(1 for page in pages if host and host in str(page.get("url") or ""))
        if count:
            lines.append("| %s | %d | 正常 |" % (seed, count))
            continue
        failed += 1
        reason = next((why for url, why in reason_by_url.items() if host and host in url), "")
        lines.append("| %s | 0 | ⚠ 采集失败：%s |"
                     % (seed, reason or "目标不可达或被拒绝，详见 ④ 的运行日志"))
    return "\n".join(lines), failed


def _render_suppressed(suppressed):
    """误报抑制附录：被白名单/抑制规则挂起的条目单独列出，保持可追溯。

    赛题要的是"可解释、可跟踪"，而不是把误报悄悄删掉——删掉就变成不可审计了。
    """

    lines = ["", "## 五、误报抑制与白名单留痕", "",
             "以下 %d 条命中被白名单/抑制规则挂起，未计入风险统计，保留在此供审计复核：" % len(suppressed), ""]
    for index, item in enumerate(suppressed, 1):
        lines.append("%d. [%s] %s" % (index, item.get("type", ""), item.get("title", "")))
        lines.append("   - 规则：`%s` ｜ 位置：%s" % (item.get("rule_id", ""), item.get("url", "")))
        lines.append("   - 抑制原因：%s" % (item.get("suppress_reason", "命中白名单/抑制规则")))
    lines.append("")
    lines.append("抑制不等于删除：条目仍保存在运行日志与审计记录里，可随时解除抑制重新纳入统计。")
    return "\n".join(lines)


def _render_markdown(findings, stats, discover, explain_map):
    pages = len(discover.get("pages", []) or [])
    blocked = discover.get("blocked", []) or []
    lines = ["# %s" % REPORT_TITLE, ""]
    lines.append("| 项目 | 内容 |")
    lines.append("| --- | --- |")
    lines.append("| 报告时间 | %s |" % time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("| 覆盖资产 | %s |" % ("、".join(sorted({f.get("asset", "") for f in findings
                                                          if f.get("asset")})) or "-"))
    lines.append("| 发现页面 | %d 个 |" % pages if pages else "| 发现页面 | - |")
    lines.append("| 原始命中 → 去重后 | %s → %s 条 |" % (stats.get("raw", "-"), stats.get("merged", "-")))
    lines.append("| 二次确证 | %s 条 |" % stats.get("verified", "-"))
    lines.append("| 合规拦截 | %d 次越界/排除请求被拒 |" % len(blocked))
    lines.append("")

    lines.append("## 一、风险概览")
    lines.append("")
    lines.append("| 等级 | 数量 |")
    lines.append("| --- | --- |")
    by_level = stats.get("by_level", {}) or {}
    for level in ("P0", "P1", "P2", "P3"):
        lines.append("| %s | %d |" % (level, by_level.get(level, 0)))
    lines.append("")
    by_type = {}
    for item in findings:
        by_type[item.get("type", "?")] = by_type.get(item.get("type", "?"), 0) + 1
    lines.append("风险类型分布：" + ("、".join("%s %d" % (k, v) for k, v in sorted(by_type.items()))
                                or "无"))
    lines.append("")

    lines.append("## 二、风险明细")
    lines.append("")
    if not findings:
        lines.append("本周期未发现风险。")
        lines.append("")
    for index, item in enumerate(findings, 1):
        explain = explain_map.get(item.get("id"), {})
        lines.append("### %d. [%s] %s" % (index, item.get("level", "?"), item.get("title", "")))
        lines.append("")
        lines.append("- 类型：%s | 规则：`%s` | 风险分：%s | 置信度：%s | 状态：%s"
                     % (item.get("type", ""), item.get("rule_id", ""), item.get("risk_score", ""),
                        item.get("confidence", ""), item.get("status", "")))
        tools = "、".join(item.get("tools") or ([item.get("tool")] if item.get("tool") else []))
        origin = {"tool": "工具线（⑤b + MCP）",
                  "both": "被动检测线（⑤）+ 工具线（⑤b + MCP）交叉印证"}.get(
            item.get("source_line"), "被动检测线（⑤）")
        lines.append("- 检测来源：%s | %s" % (origin, tools or "内置规则"))
        lines.append("- 位置：%s" % item.get("url", ""))
        affected = item.get("affected_urls", []) or []
        if len(affected) > 1:
            lines.append("- 影响页面（%d）：" % len(affected))
            for url in affected[:8]:
                lines.append("  - %s" % url)
            if len(affected) > 8:
                lines.append("  - …其余 %d 个页面略" % (len(affected) - 8))
        if item.get("cwe_name") or item.get("cwe"):
            lines.append("- 弱点分类：%s %s" % (item.get("cwe", ""), item.get("cwe_name", "")))
        lines.append("- 证据：")
        for text in (item.get("evidence") or [])[:3]:
            lines.append("  - %s" % text)
        lines.append("- 影响：%s" % (explain.get("impact") or "证据不足，建议人工复核"))
        lines.append("- 修复建议：%s" % (explain.get("remediation")
                                     or DEFAULT_REMEDIATION.get(item.get("type", ""), "建议人工评估后整改。")))
        lines.append("")

    lines.append("## 三、合规与审计摘要")
    lines.append("")
    lines.append("- 所有出站请求均经授权范围校验，命中排除规则或越界的请求一律未发出。")
    lines.append("- 本轮被拦截请求：%d 次" % len(blocked))
    for entry in blocked[:5]:
        lines.append("  - %s → %s" % (entry.get("url", ""), entry.get("reason", "")))
    lines.append("")
    lines.append("## 四、说明")
    lines.append("")
    lines.append("- 本报告由智能巡检智能体自动生成，每条结论均可回溯到证据与来源规则。")
    lines.append("- 默认仅执行被动采集（T0）与受控探测（T1）；主动验证（T2）默认关闭。")
    lines.append("- 证据中的敏感值已按策略脱敏，原始值单独加密存储。")
    return "\n".join(lines)


def _render_html(findings, stats, discover, explain_map):
    rows = []
    for index, item in enumerate(findings, 1):
        explain = explain_map.get(item.get("id"), {})
        level = str(item.get("level", ""))
        color = {"P0": "#c0392b", "P1": "#e67e22", "P2": "#f1c40f", "P3": "#7f8c8d"}.get(level, "#7f8c8d")
        evidence = "".join("<li>%s</li>" % _esc(t) for t in (item.get("evidence") or [])[:3])
        rows.append(
            "<tr><td>%d</td><td><span style='color:%s;font-weight:700'>%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><ul>%s</ul></td></tr>"
            % (index, color, _esc(level), _esc(item.get("title", "")), _esc(item.get("asset", "")),
               _esc(item.get("risk_score", "")), _esc(item.get("status", "")),
               _esc(explain.get("impact") or "证据不足，建议人工复核"),
               _esc(explain.get("remediation") or DEFAULT_REMEDIATION.get(item.get("type", ""), "")),
               evidence))
    by_level = stats.get("by_level", {}) or {}
    return (
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'><title>%s</title>"
        "<style>body{font-family:'Microsoft YaHei',sans-serif;margin:24px;color:#1f2a37}"
        "table{border-collapse:collapse;width:100%%;margin-top:12px}"
        "th,td{border:1px solid #d7dee6;padding:8px;font-size:13px;vertical-align:top;text-align:left}"
        "th{background:#f4f7fa}h1{font-size:20px}h2{font-size:16px;margin-top:22px}"
        ".kpi{display:inline-block;margin-right:18px}.kpi b{color:#c0392b;font-size:18px}</style></head>"
        "<body><h1>%s</h1>"
        "<p><span class='kpi'>原始命中 <b>%s</b></span><span class='kpi'>去重后 <b>%s</b></span>"
        "<span class='kpi'>P0 <b>%s</b></span><span class='kpi'>P1 <b>%s</b></span>"
        "<span class='kpi'>二次确证 <b>%s</b></span><span class='kpi'>合规拦截 <b>%s</b> 次</span></p>"
        "<h2>风险明细</h2><table><tr><th>#</th><th>等级</th><th>风险</th><th>资产</th><th>风险分</th>"
        "<th>状态</th><th>影响</th><th>修复建议</th><th>证据</th></tr>%s</table>"
        "<h2>说明</h2><p>本报告由智能巡检智能体自动生成，结论均可回溯到证据与来源规则；"
        "所有出站请求均经授权范围校验，越界请求未发出。</p></body></html>"
        % (REPORT_TITLE, REPORT_TITLE, stats.get("raw", "-"), stats.get("merged", "-"),
           by_level.get("P0", 0), by_level.get("P1", 0), stats.get("verified", "-"),
           len(discover.get("blocked", []) or []), "".join(rows)))


def _build_alert(findings, stats, discover):
    by_level = stats.get("by_level", {}) or {}
    hot = [f for f in findings if f.get("level") in ALERT_MIN_LEVELS]
    if not hot:
        return {"triggered": False, "level": "", "channel": "", "sent": False, "payload": ""}
    level = "P0" if by_level.get("P0") else "P1"
    payload = {
        "title": "[%s] 网站安全巡检告警：P0 %d 条 / P1 %d 条"
                 % (level, by_level.get("P0", 0), by_level.get("P1", 0)),
        "asset": "、".join(sorted({f.get("asset", "") for f in hot if f.get("asset")})),
        "summary": "本轮原始命中 %s 条，去重后 %s 条，其中 %d 条高危；越界请求拦截 %d 次。"
                   % (stats.get("raw"), stats.get("merged"), len(hot),
                      len(discover.get("blocked", []) or [])),
        "top": [{"level": f.get("level"), "title": f.get("title"), "url": f.get("url")}
                for f in hot[:3]],
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"triggered": True, "level": level, "channel": ALERT_WEBHOOK or "未配置", "sent": False,
            "payload": json.dumps(payload, ensure_ascii=False)}


def _send_alert(alert):
    if not (alert.get("triggered") and ALERT_WEBHOOK):
        return False
    try:
        request = urllib.request.Request(
            ALERT_WEBHOOK, data=alert["payload"].encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=8) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def handler(args: Args) -> dict:
    global ALERT_WEBHOOK
    try:
        # 告警通道从 ② 交互节点收集的变量读取（webhook:https://… 或 email:…）
        channel = str(_input(args, "alert_channel") or "").strip()
        if channel.startswith("webhook:"):
            ALERT_WEBHOOK = channel.split("webhook:", 1)[1].strip()
        findings_data = _unwrap(_input(args, "findings_payload"))
        explain_raw = _input(args, "explain_payload")
        discover = _unwrap(_input(args, "discover_payload"))

        findings = findings_data.get("findings", []) or []
        stats = findings_data.get("stats", {}) or {}
        # 白名单抑制的条目不进正文，单独列在报告附录里，保证"抑制过什么"可追溯
        suppressed = [item for item in findings if str(item.get("status")) == "suppressed"]
        findings = [item for item in findings if str(item.get("status")) != "suppressed"]
        explanations = _parse_explanations(explain_raw)
        explain_source = "上游模型节点" if explanations else ""
        # 上游（⑦）可能只解释了一部分，缺的那些由本节点自调模型补齐
        covered = {str(item.get("id")) for item in explanations if isinstance(item, dict)}
        missing = [item for item in findings if str(item.get("id")) not in covered]
        if missing:
            filled = _ask_model(missing)
            if filled:
                explanations = explanations + filled
                explain_source = ("上游模型节点 + 本节点补齐 %d 条" % len(filled)) if covered \
                    else "本节点内置调用"
            elif not explanations:
                explain_source = "内置模板兜底"
        print("[报告与告警][调试] explain 原始前 300 字：%s" % str(explain_raw)[:300])
        print("[报告与告警][调试] 解析出解释条数：%d / 待解释风险：%d"
              % (len(explanations), len(findings)))
        # 模型可能自己编号，所以除了按 id 匹配，再按序号与顺序兜底
        by_id = {}
        for position, item in enumerate(explanations, 1):
            if not isinstance(item, dict):
                continue
            for key in (item.get("id"), item.get("ID"), item.get("_id"), position):
                if key is not None:
                    by_id.setdefault(str(key), item)
        explain_map = {}
        for position, finding in enumerate(findings, 1):
            candidate = by_id.get(str(finding.get("id"))) or by_id.get(str(position))
            if candidate is None and position - 1 < len(explanations):
                tail = explanations[position - 1]
                candidate = tail if isinstance(tail, dict) else None
            if candidate:
                explain_map[str(finding.get("id"))] = candidate

        markdown = _render_markdown(findings, stats, discover, explain_map)
        if suppressed:
            markdown = markdown + "\n" + _render_suppressed(suppressed)
        html = _render_html(findings, stats, discover, explain_map)
        # 一页都没抓到却出"0 风险"报告，是最容易骗过自己的假阴性：
        # 报告必须显式说明"结果不可用"，并给出排查方向。
        pages = discover.get("pages") or []
        collect_warning = ""
        if not pages:
            collect_warning = (
                "⚠ 本轮未采集到任何页面，报告结果不可用。"
                "常见原因：授权目标为空 / 填成了 site_id（如 demo-local）而不是可达地址 / "
                "填了平台访问不到的地址（如 127.0.0.1）。请检查 ③ 的授权目标与 ④ 的运行日志后重跑。")
            markdown = "> " + collect_warning + "\n\n" + markdown
        targets_block, failed_targets = _render_targets(discover, findings)
        if targets_block:
            markdown = markdown + "\n" + targets_block
        observed_hosts = _observed_hosts(findings, discover)
        markdown, fixed_md = _guard_urls(markdown, observed_hosts)
        html, _ = _guard_urls(html, observed_hosts)      # HTML 同样纠偏，计数只报正文那份
        fixed_urls = fixed_md
        alert = _build_alert(findings, stats, discover)
        alert["sent"] = _send_alert(alert)

        covered = len(explain_map)
        summary = ("报告已生成：风险 %d 条（P0 %d / P1 %d / P2 %d / P3 %d），"
                   "模型已解释 %d 条%s；告警%s。"
                   % (len(findings), (stats.get("by_level") or {}).get("P0", 0),
                      (stats.get("by_level") or {}).get("P1", 0),
                      (stats.get("by_level") or {}).get("P2", 0),
                      (stats.get("by_level") or {}).get("P3", 0), covered,
                      "" if covered >= len(findings) else "（其余用内置模板兜底）",
                      ("已触发 %s 级，%s" % (alert["level"],
                                          "已推送" if alert["sent"] else "未配置通道，仅生成告警内容"))
                      if alert["triggered"] else "未达到触发条件，仅录入报告"))
        if not alert["triggered"]:
            alert_line = "告警：未达到触发条件（无 P0/P1），仅录入报告"
        elif alert["sent"]:
            alert_line = "告警：已触发 %s 级，已推送至配置的通道" % alert["level"]
        elif ALERT_WEBHOOK:
            alert_line = "告警：已触发 %s 级，但推送失败（通道 %s 不可达），内容已生成" % (
                alert["level"], ALERT_WEBHOOK[:60])
        else:
            alert_line = "告警：已触发 %s 级，未配置通道，仅生成告警内容" % alert["level"]
        source_line = "模型解释：%d / %d 条（来源：%s）" % (len(explain_map), len(findings),
                                                       explain_source or "无")
        coverage_line = ("覆盖：页面 %d 个 / 越界拦截 %d 次 / 原始命中 %s → 去重后 %s"
                         % (len(discover.get("pages", []) or []),
                            len(discover.get("blocked", []) or []),
                            stats.get("raw", "-"), stats.get("merged", "-")))
        if targets_block:
            seed_total = len((discover.get("stats") or {}).get("seed_urls") or [])
            coverage_line += " / 授权目标 %d 个（失败 %d 个）" % (seed_total, failed_targets)
        mix = stats.get("by_source") or {}
        mix_line = ("来源构成：被动检测线（⑤）%d 条 · 工具线（⑤b + MCP）%d 条 · 两线交叉印证 %d 条"
                    % (mix.get("passive", 0), mix.get("tool", 0),
                       stats.get("cross_verified", 0))) if mix else ""
        false_positive = len([item for item in findings if str(item.get("status")) == "needs_review"])
        tool_pending = len([item for item in findings if str(item.get("source_line")) in ("tool",)
                            and str(item.get("status")) == "unverified"])
        fp_line = ("误报处置：复采未命中转待复核 %d 条 · 白名单抑制 %d 条 · 工具线待工具复测 %d 条"
                   % (false_positive, len(suppressed), tool_pending))

        # 输出为一段可直接阅读的文本：摘要 → 报告正文 → 报告交付 → 运行数据
        stamp = _task_stamp()
        csv_text = _render_csv(findings, explain_map, suppressed)
        payload_json = json.dumps({"findings": findings, "suppressed": suppressed, "stats": stats},
                                  ensure_ascii=False, indent=2)
        exports = {
            "html": ("report_%s.html" % stamp, html, EXPORT_MIME["html"]),
            "csv": ("report_%s.csv" % stamp, csv_text, EXPORT_MIME["csv"]),
            "markdown": ("report_%s.md" % stamp, markdown, EXPORT_MIME["markdown"]),
            "json": ("report_%s.json" % stamp, payload_json, EXPORT_MIME["json"]),
        }
        saved = _save_exports(exports)
        delivery, link_count = _render_delivery(exports, saved)

        text_lines = [summary, "", markdown, delivery, "—— 运行数据 ——",
                      coverage_line, alert_line, source_line]
        if collect_warning:
            text_lines.insert(1, collect_warning)
            text_lines.append("采集校验：页面 0 个 → 本轮结果不可用，请勿据此判定「无风险」")
        text_lines.append(fp_line)
        if mix_line:
            text_lines.append(mix_line)
        if fixed_urls:
            text_lines.append("证据纠偏：%d 处被模型抄错的域名已回正为实测域名" % fixed_urls)
            print("[报告与告警] 证据纠偏 %d 处：模型输出的域名与实测不符，已回正" % fixed_urls)
        text_lines.append("报告交付：HTML/CSV/Markdown/JSON 四种格式%s，可下载链接 %d 个"
                          % ("已落盘" if saved else "已生成（文本内交付）", link_count))
        full_text = "\n".join(text_lines)
        print("[报告与告警] " + summary)
        print("-" * 60)
        print(full_text)
        print("-" * 60)
        return {"result_key": full_text}
    except Exception as exc:
        print("[报告与告警] 执行异常：%s" % exc)
        return {"result_key": json.dumps({"summary": "报告生成异常：%s" % exc, "report": {},
                                          "alert": {"triggered": False}, "stats": {}},
                                         ensure_ascii=False)}
