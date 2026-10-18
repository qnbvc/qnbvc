# coding=utf-8
"""⑤c 代码节点 · 工具线输出规范化（⑤b 与 ⑥ 之间的保险丝）。

为什么需要它
------------
自规划（Agent）节点的输出 = 模型的最终回复。模型调完 MCP 工具后很容易写成
"非常好！现在我有了完整的证书信息。让我分析一下：……" 这样的自然语言，
而不是提示词要求的 JSON 数组。⑥ 的容错规则会把这种输出整条忽略，
于是工具线看起来"跑了但没有结果"。

职责
----
把 ⑤b 的任意输出归一成统一 Finding 数组：
    1) 已经是 JSON 数组 → 直接采用；
    2) 输出是带说明文字的文本 → 抠出其中的 JSON（优先最后的、像风险清单的那一段）；
    3) 抠不出来 → 输出 []，并把原文摘要放进 note，绝不猜测、绝不编造；
    4) 补齐缺字段（url / tool / tier / severity / confidence），缺 url 时用授权范围里的域名补。

输入：
    tool_payload   ⑤b 自规划节点的 result_key（文本或 JSON）
    mcp_payload    ⑤d 工具节点（调用 run_inspection 这类能力集）的 result_key，可选
    scope_payload  ③ 策略校验的 result_key（可选，用于补 asset / url）

输出（result_key，JSON 字符串）：
    {"findings": [...], "note": "...", "raw_chars": 1234}
"""

from runtime import Args

import json
import re

FINDING_KEYS = ("title", "rule_id", "type", "severity", "evidence")
DEFAULT_TOOL = "自规划工具线"

# 能力集返回的类别与等级是中文（漏洞/配置缺陷/组件风险/敏感信息/挂马篡改、严重/高/中/低），
# 我们内部用英文枚举参与加权计算，这里做一次翻译，否则"严重"会被当成未知等级按 info 计权。
TYPE_ALIASES = (
    ("vuln", ("漏洞", "sql", "xss", "注入", "遍历", "上传", "弱口令", "越权", "反序列化")),
    ("tamper", ("篡改", "基线", "内容变更")),
    ("malware", ("挂马", "暗链", "恶意", "挖矿", "webshell", "木马", "外链")),
    ("leak", ("敏感", "泄露", "泄漏", "凭据", "密钥", "口令", "备份", "源码", "个人信息")),
    ("misconfig", ("配置", "组件", "响应头", "未授权", "目录", "cors", "cookie", "版本", "证书")),
)
SEVERITY_ALIASES = (
    ("critical", ("严重", "critical", "urgent")),
    ("high", ("高", "high")),
    ("medium", ("中", "medium", "moderate")),
    ("low", ("低", "low")),
    ("info", ("信息", "提示", "info", "note")),
)


def _canonical_type(value, fallback="misconfig"):
    text = str(value or "").strip().lower()
    if text in ("vuln", "misconfig", "leak", "malware", "tamper"):
        return text
    for canonical, aliases in TYPE_ALIASES:
        for alias in aliases:
            if alias in text:
                return canonical
    return fallback


def _canonical_severity(value, fallback="medium"):
    text = str(value or "").strip().lower()
    if text in ("critical", "high", "medium", "low", "info"):
        return text
    for canonical, aliases in SEVERITY_ALIASES:
        for alias in aliases:
            if alias in text:
                return canonical
    return fallback


# 能力集返回的置信度不一定是数字：实测出现过 "confirmed" 这类文字，
# 直接 float() 会让节点整个崩掉（线上报错：could not convert string to float: 'confirmed'）。
CONFIDENCE_WORDS = (
    ("confirm", 0.9), ("verif", 0.9), ("high", 0.9), ("确定", 0.9), ("已确认", 0.9),
    ("likely", 0.75), ("probable", 0.75), ("medium", 0.75), ("可能", 0.75),
    ("suspect", 0.6), ("疑似", 0.6), ("low", 0.5), ("tentative", 0.5), ("info", 0.5),
)


def _to_confidence(value, default=0.75):
    """把任意形态的置信度收敛成 0~1 的小数，认不出来就用默认值，绝不抛异常。"""

    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value or "").strip()
        if not text:
            return default
        try:
            number = float(text)
        except ValueError:
            lowered = text.lower()
            for word, score in CONFIDENCE_WORDS:
                if word in lowered:
                    return score
            return default
    if number > 1:                       # 有的工具用百分数（95 表示 95%）
        number = number / 100.0 if number <= 100 else 1.0
    return round(max(0.0, min(1.0, number)), 2)


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
            return default
    return raw if raw is not None else default


def _as_text(raw):
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, ensure_ascii=False)
    except Exception:
        return str(raw)


def _unwrap(raw):
    """逐层剥掉平台引用时包的 {"result_key": ...} 外壳，直到拿到内层最里层的字符串/对象。"""

    payload = _load(raw, None)
    for _ in range(4):
        if isinstance(payload, dict) and "result_key" in payload:
            inner = _load(payload["result_key"], None)
            if inner is not None:
                payload = inner
                continue
        break
    return payload


def _json_arrays(text):
    """扫出文本里所有合法的 JSON 数组（按括号深度配平，跳过字符串里的括号）。"""

    results = []
    index = 0
    while index < len(text):
        if text[index] != "[":
            index += 1
            continue
        depth = 0
        in_string = False
        escaped = False
        for position in range(index, len(text)):
            char = text[position]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[index:position + 1])
                        if isinstance(parsed, list):
                            results.append((index, parsed))
                    except Exception:
                        pass
                    index = position + 1
                    break
        else:
            break
    return results


def _looks_like_findings(items):
    if not items or not all(isinstance(item, dict) for item in items):
        return False
    return any(key in item for item in items for key in FINDING_KEYS)


def _extract(text):
    """从任意文本里取出风险清单数组：优先"像风险清单"的、靠后的那一段。"""

    arrays = _json_arrays(text)
    if not arrays:
        return None, "文本里没有找到 JSON 数组"
    findings = [(position, items) for position, items in arrays if _looks_like_findings(items)]
    if findings:
        position, items = findings[-1]
        return items, "从文本中提取到风险清单（位置 %d）" % position
    position, items = arrays[-1]
    if items == []:
        return [], "文本中的 JSON 数组为空，判定为未发现问题"
    return None, "找到了 JSON 数组（位置 %d），但内容不是风险条目，已忽略" % position


def _extract_pending(payload, text):
    """取出工具线登记的"待授权确认资产"（子域名发现这类工具的产出）。

    这些资产不在授权清单内，所以只登记、不探测；记下来是为了在报告里体现
    "发现了范围外资产但克制住没有碰"这个动作，对应赛题的授权边界评分点。
    """

    if isinstance(payload, dict):
        for key in ("pending_assets", "new_assets", "subdomains", "discovered_hosts"):
            value = payload.get(key)
            if isinstance(value, list):
                return [str(item) for item in value if str(item).strip()]
            if isinstance(value, str) and value.strip():
                return [part.strip() for part in re.split(r"[,\s;]+", value) if part.strip()]
    match = re.search(r'"(?:pending_assets|new_assets|subdomains)"\s*:\s*(\[[^\]]*\])', text)
    if match:
        parsed = _load(match.group(1), None)
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item).strip()]
    return []


def _scope_hosts(scope):
    hosts = []
    for source in (scope.get("scope_snapshot"), scope):
        data = _load(source, None) if isinstance(source, str) else source
        if not isinstance(data, dict):
            continue
        for key in ("active_assets", "domains", "exact_domains"):
            for host in data.get(key) or []:
                host = str(host).strip()
                if host and host not in hosts:
                    hosts.append(host)
    return hosts


def _normalize(items, hosts, counters):
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            counters["dropped"] += 1
            continue
        # 能力集会把"没问题的检查项"也列出来（effect=positive），那不是风险
        if str(item.get("effect") or "").strip().lower() in ("positive", "ok", "pass", "passed"):
            counters["skipped_positive"] = counters.get("skipped_positive", 0) + 1
            continue
        title = str(item.get("title") or item.get("name") or "").strip()
        rule_id = str(item.get("rule_id") or item.get("id") or "").strip()
        if not title and not rule_id:
            counters["dropped"] += 1
            continue
        url = str(item.get("url") or "").strip()
        asset = str(item.get("asset") or "").strip()
        if not asset and url:
            match = re.match(r"(?i)^https?://([^/?#\s]+)", url)
            asset = match.group(1) if match else ""
        if not asset and hosts:
            asset = hosts[0]
            counters["filled_host"] += 1
        if not url and asset:
            url = "https://%s/" % asset
            counters["filled_host"] += 1
        evidence = item.get("evidence") or ""
        if isinstance(evidence, (list, tuple)):
            evidence = evidence[0] if evidence else ""
        normalized.append({
            "asset": asset,
            "url": url,
            "type": _canonical_type(item.get("type") or item.get("category") or ""),
            "rule_id": rule_id or ("TOOL.%s" % title[:24].replace(" ", "_")),
            "title": title or rule_id,
            "severity": _canonical_severity(item.get("severity") or item.get("level") or ""),
            "tool": str(item.get("tool") or DEFAULT_TOOL),
            "tier": str(item.get("tier") or "T1"),
            "location": str(item.get("location") or "工具检测项"),
            "evidence": str(evidence),
            "verify_hint": str(item.get("verify_hint") or ""),
            "confidence": _to_confidence(item.get("confidence")),
            "external_id": str(item.get("external_id") or item.get("id") or ""),
        })
    return normalized


LIST_KEYS = ("findings", "results", "items", "data", "risks", "issues", "vulnerabilities")
WRAP_KEYS = ("content", "text", "output", "result", "result_key", "message", "body")


def _shape(payload):
    """把上游结构压成一行，便于从日志里直接看出"它到底返回了什么"。"""

    if isinstance(payload, dict):
        parts = []
        for key, value in list(payload.items())[:10]:
            if isinstance(value, list):
                fields = sorted({k for item in value if isinstance(item, dict) for k in item})
                parts.append("%s:数组[%d]字段%s" % (key, len(value), fields[:8]))
            elif isinstance(value, dict):
                parts.append("%s:对象%s" % (key, list(value.keys())[:6]))
            else:
                parts.append("%s:%s" % (key, type(value).__name__))
        return " | ".join(parts)
    if isinstance(payload, list):
        fields = sorted({k for item in payload if isinstance(item, dict) for k in item})
        return "数组[%d]字段%s" % (len(payload), fields[:8])
    return type(payload).__name__


def _dig(value, depth=0):
    """挖出真正的清单：兼容工具节点/MCP 的各种包装（content / text / result_key / 内层 JSON 字符串）。

    代码节点的输出是我们在代码里 return 的 {"result_key": ...}，而工具节点的输出由平台按
    MCP 协议包装（常见是 {"content": [{"type": "text", "text": "<json>"}]}），字段名不一样。
    """

    if depth > 5:
        return None
    if isinstance(value, dict):
        for key in LIST_KEYS:
            if isinstance(value.get(key), list):
                return value[key]
        for key in WRAP_KEYS:
            if key in value:
                found = _dig(value[key], depth + 1)
                if found is not None:
                    return found
        return None
    if isinstance(value, list):
        # 本身就是一份风险清单（元素带 title/rule_id/severity/category 这类字段）。
        # 注意不能只看 type——MCP 包装 [{"type":"text","text":"…"}] 里也有 type 字段。
        if value and any(isinstance(item, dict) and any(
                key in item for key in ("title", "rule_id", "severity", "category", "evidence"))
                for item in value):
            return value
        texts = []
        for item in value:
            found = _dig(item, depth + 1) if isinstance(item, dict) else None
            if found is not None:
                return found
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                texts.append(item["text"])
        if texts:
            return _dig("\n".join(texts), depth + 1)
        return None
    if isinstance(value, str):
        parsed = _load(value, None)
        if parsed is not None and not isinstance(parsed, str):
            found = _dig(parsed, depth + 1)
            if found is not None:
                return found
        items, _note = _extract(value)
        return items
    return None


def _host_of(value):
    """从 url / asset 里取出 host[:port]。"""

    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"(?i)^https?://([^/?#\s]+)", text)
    if match:
        return match.group(1).rstrip("/").lower()
    if re.match(r"^[A-Za-z0-9._-]+(:\d+)?$", text) and "." in text:
        return text.lower()
    return ""


def _scope_filter(findings, hosts, label, counters):
    """目标一致性闸门：工具线/能力集扫的必须是本轮授权目标，否则整条隔离。

    实测遇到过：能力集用 site_id 扫自己服务器上的 demo-local（127.0.0.1:8080），
    而本轮授权目标是 demo.testfire.net——两份结果毫无关系。若直接合并，
    报告标题写着一个站点、明细里却全是另一个站点的风险，属于证据错配，
    比"少几条数据"严重得多。
    """

    if not hosts:
        return findings, []
    allowed = {str(item).lower() for item in hosts}
    allowed_names = {item.split(":")[0] for item in allowed}
    kept, isolated = [], []
    for item in findings:
        host = ""
        for value in (item.get("url"), item.get("asset")):
            host = _host_of(value)
            if host:
                break
        if not host:
            kept.append(item)
            continue
        if host in allowed or host.split(":")[0] in allowed_names:
            kept.append(item)
            continue
        isolated.append({"url": item.get("url", ""), "host": host, "title": item.get("title", "")})
    if isolated:
        counters["isolated"] = counters.get("isolated", 0) + len(isolated)
        print("[工具线规范化] ⚠ %s 有 %d 条结果不属于本轮授权目标，已整条隔离（避免证据错配）："
              "host=%s；授权目标=%s"
              % (label, len(isolated), "、".join(sorted({i["host"] for i in isolated})[:5]),
                 "、".join(sorted(allowed)[:5])))
    return kept, isolated


def _collect(raw, label, hosts, counters):
    """把一路上游输出解析成 (条目列表, 说明, 待授权资产)。"""

    text = _as_text(raw)
    print("[工具线规范化] %s 入参字符数=%d / 开头=%s"
          % (label, len(text), text[:160].replace("\n", " ")))
    if not text.strip():
        print("[工具线规范化] %s 无输出（可能未执行或已被异常配置兜底）" % label)
        return [], "%s 无输出" % label, []

    payload = _unwrap(raw)
    items = _dig(payload)
    if items is not None:
        note = "从上游输出中识别出清单"
    else:
        items, note = _extract(text)
    if items is None:
        items = []
        note = "%s（未识别出清单，上游结构：%s）" % (note, _shape(payload))
    findings = _normalize(items, hosts, counters)
    print("[工具线规范化] %s：%s；归一后 %d 条" % (label, note, len(findings)))
    return findings, "%s：%s" % (label, note), _extract_pending(payload, text)


def handler(args: Args) -> dict:
    raw_tool = _input(args, "tool_payload")
    raw_mcp = _input(args, "mcp_payload")
    scope = _unwrap(_input(args, "scope_payload")) or {}
    hosts = _scope_hosts(scope if isinstance(scope, dict) else {})
    counters = {"dropped": 0, "filled_host": 0}

    findings, tool_note, pending = _collect(raw_tool, "⑤b 自规划工具线", hosts, counters)
    mcp_findings, mcp_note, mcp_pending = _collect(raw_mcp, "⑤d 能力集工具", hosts, counters)
    findings, isolated_tool = _scope_filter(findings, hosts, "⑤b 自规划工具线", counters)
    mcp_findings, isolated_mcp = _scope_filter(mcp_findings, hosts, "⑤d 能力集工具", counters)
    findings = findings + mcp_findings
    pending = list(dict.fromkeys(pending + mcp_pending))
    note = "%s ｜ %s；合计 %d 条，丢弃不完整条目 %d 条" % (
        tool_note, mcp_note, len(findings), counters["dropped"])
    isolated = isolated_tool + isolated_mcp
    if isolated:
        note += "；隔离 %d 条（host 不在本轮授权目标）" % len(isolated)
    print("[工具线规范化] " + note)
    for item in findings:
        print("[工具线规范化]   - [%s|%s] %s（%s）"
              % (item["type"], item["severity"], item["title"], item["rule_id"]))
    if pending:
        print("[工具线规范化] 待授权确认资产 %d 个（只登记、未探测）：%s"
              % (len(pending), "、".join(pending[:10])))
    return {"result_key": json.dumps({"findings": findings, "note": note, "pending_assets": pending,
                                      "isolated": isolated,
                                      "tool_chars": len(_as_text(raw_tool)),
                                      "mcp_chars": len(_as_text(raw_mcp))}, ensure_ascii=False)}
