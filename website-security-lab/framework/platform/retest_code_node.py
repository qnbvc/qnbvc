# coding=utf-8
"""⑨b 代码节点 · 复测（对已上报风险重新确证）。

为什么这样设计
--------------
"复测"不是"再跑一遍全量巡检"，而是**对已经上报的风险重新确认一遍**：
整改之后逐条复采，判断"仍存在 / 已修复 / 无法判定"。
这样就不需要跨轮持久化基线（平台没有变量赋值节点），也不需要让流程成环。

输入：
    findings_payload   ⑥ 代码_去重验证分级的 result_key
    report_payload     ⑧ 代码_报告生成与告警的 result_key（可选）
                       给了就在末尾输出"报告正文 + 复测结论"的合并版，作为最终交付
    review_action      ⑨ 交互_复核与复测 的 review_action（用户选的处理方式）

输出（result_key，Markdown 文本）：
    复测结论表格 + 统计 + 建议；没有请求复测时输出一句说明。

合规：只读 GET、单目标限速、带自定义 UA；不对未上报的路径发起任何请求。
"""

from runtime import Args

import json
import time
import urllib.request

# ------------------------- 可调参数 -------------------------
MAX_RETEST = 20                 # 单轮最多复测多少条（按风险分从高到低取）
DELAY_PER_HOST = 0.3            # 同一主机的请求间隔
RETEST_TIMEOUT = 8
USER_AGENT = "SecurityInspector/1.0 (+authorized-retest)"
RETEST_WORD = "复测"
INCLUDE_REPORT = True           # 末尾是否连同报告正文一起输出（合并交付）
# -----------------------------------------------------------


def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def _text(value):
    """交互节点的答案可能是 {_question,_answer,...} / {A:...} / 纯字符串。"""

    if isinstance(value, dict):
        if "_answer" in value:
            return _text(value["_answer"])
        return "、".join(part for part in (_text(item) for item in value.values()) if part)
    if isinstance(value, (list, tuple)):
        return "、".join(part for part in (_text(item) for item in value) if part)
    return "" if value is None else str(value)


def _unwrap(raw, default=None):
    payload = raw
    for _ in range(4):
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return default if default is not None else {}
            continue
        if isinstance(payload, dict) and "result_key" in payload:
            payload = payload["result_key"]
            continue
        break
    return payload if isinstance(payload, (dict, list)) else (default if default is not None else {})


def _http_get(url):
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
    try:
        with urllib.request.urlopen(request, timeout=RETEST_TIMEOUT) as response:
            raw = response.read(500_000)
            try:
                return response.status, raw.decode("utf-8")
            except UnicodeDecodeError:
                return response.status, raw.decode("gb18030", "ignore")
    except Exception:
        return 0, ""


def _retest_one(finding):
    """复测单条：返回 (结论, 依据)。结论只有 仍存在 / 已修复 / 无法判定。"""

    url = finding.get("url") or (finding.get("affected_urls") or [""])[0]
    if not url:
        return "无法判定", "该条没有可复采的位置"
    status, text = _http_get(url)
    if status == 0 and str(url).startswith("https://"):
        status, text = _http_get("http://" + str(url)[len("https://"):])
    if status != 200:
        return "无法判定", "复采未取到页面（HTTP %s）" % (status or "连接失败")

    hint = str(finding.get("verify_hint") or "").strip()
    ftype = str(finding.get("type") or "")
    if hint:
        if hint in text:
            return "仍存在", "复采仍命中：%s" % hint[:40]
        return "已修复", "复采已不再命中：%s" % hint[:40]
    if ftype == "vuln":
        return "仍存在", "敏感资源仍可访问（HTTP 200）"
    if ftype == "misconfig":
        return "仍存在", "配置类结论需以响应头/配置复采为准，建议用同一工具复测"
    if ftype == "leak":
        return "仍存在", "该页面仍可访问且未被拦截"
    return "无法判定", "非确定性结论，需人工或同工具复测"


def _report_text(raw):
    """取 ⑧ 的报告正文：可能是纯文本，也可能被包了一层 {"result_key": "..."}。"""

    if isinstance(raw, dict) and "result_key" in raw:
        return _report_text(raw["result_key"])
    return "" if raw is None else str(raw)


def handler(args: Args) -> dict:
    started = time.time()
    action = _text(_input(args, "review_action"))
    data = _unwrap(_input(args, "findings_payload"), {})
    findings = data.get("findings", []) if isinstance(data, dict) else (data or [])
    findings = [item for item in findings if isinstance(item, dict)]
    # 报告正文是纯文本，不走 _unwrap（那是给 JSON 用的）
    report = _report_text(_input(args, "report_payload")) if INCLUDE_REPORT else ""
    prefix = (report.rstrip() + "\n\n") if report else ""

    if RETEST_WORD not in action:
        print("[复测] 未请求复测（复核选择：%s）" % (action or "未作答"))
        return {"result_key": prefix +
                "本次未请求复测（复核选择：%s）。如需复测，请在复核时选择「需要复测」。"
                % (action or "未作答")}
    if not findings:
        return {"result_key": prefix + "已请求复测，但本轮没有可供复测的风险条目。"}

    ordered = sorted(findings, key=lambda f: float(f.get("risk_score") or 0), reverse=True)[:MAX_RETEST]
    rows, still, fixed, unknown = [], 0, 0, 0
    last_host = ""
    for item in ordered:
        url = str(item.get("url") or "")
        host = url.split("/")[2] if "://" in url else ""
        if host and host == last_host:
            time.sleep(DELAY_PER_HOST)
        last_host = host
        verdict, reason = _retest_one(item)
        if verdict == "仍存在":
            still += 1
        elif verdict == "已修复":
            fixed += 1
        else:
            unknown += 1
        rows.append("| %s | %s | %s | %s | %s |"
                    % (item.get("id", "-"), item.get("level", "-"),
                       str(item.get("title", ""))[:30], verdict, reason))

    lines = ["", "—— 复测结论 ——", "",
             "复测时间：%s ｜ 复测条目：%d 条（只读复采，未发起任何破坏性请求）"
             % (time.strftime("%Y-%m-%d %H:%M:%S"), len(ordered)), "",
             "| 编号 | 等级 | 风险 | 复测结论 | 依据 |", "| --- | --- | --- | --- | --- |"]
    lines.extend(rows)
    lines.append("")
    lines.append("统计：仍存在 %d 条 · 已修复 %d 条 · 无法判定 %d 条" % (still, fixed, unknown))
    lines.append("")
    if fixed:
        lines.append("- 已修复 %d 条：可关闭对应工单，并在下一轮基线中标注为已处置。" % fixed)
    if still:
        lines.append("- 仍存在 %d 条：整改尚未生效，需继续跟进；下一轮巡检仍会复现。" % still)
    if unknown:
        lines.append("- 无法判定 %d 条：建议用同一工具或人工复核后定性。" % unknown)
    lines.append("- 复测口径：对已上报条目逐条只读复采，不新增探测范围，不发起主动验证。")

    text = prefix + "\n".join(lines)
    print("[复测] 复测 %d 条（仍存在 %d / 已修复 %d / 无法判定 %d，耗时 %.1fs）"
          % (len(ordered), still, fixed, unknown, time.time() - started))
    return {"result_key": text}
