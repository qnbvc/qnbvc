# coding=utf-8
"""⑥ 代码节点 · 去重 · 验证 · 分级。

输入：
    findings_payload       ⑤ 三类检测的 result_key（JSON 字符串）—— 主线，必须绑 ⑤
    tool_findings_payload  ⑤b 自规划 + MCP 工具线的 result_key（可选，绑 ⑤b）
                           解析不出来时按"没有补充结果"处理，不会中断主流程

输出（result_key，JSON 字符串）：
    {
      "findings": [{"id","type","rule_id","title","severity","level","risk_score",
                    "confidence","verified","status","asset","url","affected_urls",
                    "occurrences","location","evidence","tool","tier","cwe"}],
      "stats":    {"raw","merged","verified","needs_review","by_level","requests","seconds"}
    }

三步：
    1) 去重聚合：同一「类型 + 规则 + 位置」跨页面合并为一条，列出 affected_urls；
    2) 非破坏性验证：只读复采原页面，命中仍存在 → verified，未复现 → needs_review 并降置信度；
    3) 分级：风险分 = 严重度 × 可达性 × 资产重要性 × 置信度，映射 P0~P3。

注意：只发 GET、限速、带自定义 UA；验证请求同样只针对已抓取的授权范围内 URL。
"""

from runtime import Args

import hashlib
import json
import re
import time
import urllib.error
import urllib.request

# ------------------------- 可调参数 -------------------------
SEVERITY_WEIGHT = {"critical": 1.00, "high": 0.70, "medium": 0.45, "low": 0.18, "info": 0.05}
LEVEL_THRESHOLDS = ((0.60, "P0"), (0.38, "P1"), (0.15, "P2"), ("P3", "P3"))
LEVEL_THRESHOLDS = (("P0", 0.60), ("P1", 0.38), ("P2", 0.15), ("P3", 0.0))
ASSET_CRITICALITY = 0.70      # 资产重要性（接入 CMDB 后可按资产取值）
REACHABILITY = 1.0            # 互联网可达
MAX_VERIFY = 12               # 单次最多复采验证多少条（按风险从高到低）
VERIFY_TIMEOUT = 8
DELAY_PER_HOST = 0.3
USER_AGENT = "SecurityInspector/1.0 (+authorized-scan; contact=secops@example.gov.cn)"
CWE_MAP = {
    "leak": "CWE-200", "misconfig": "CWE-16", "vuln": "CWE-538",
    "malware": "CWE-506", "tamper": "CWE-345",
}
# -----------------------------------------------------------


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


CONFIDENCE_WORDS = (
    ("confirm", 0.9), ("verif", 0.9), ("high", 0.9), ("确定", 0.9),
    ("likely", 0.75), ("probable", 0.75), ("medium", 0.7), ("可能", 0.7),
    ("suspect", 0.5), ("疑似", 0.5), ("low", 0.5), ("tentative", 0.4), ("info", 0.4),
)


def _safe_confidence(value, default=0.6):
    """上游给来的置信度可能是文字（如 "confirmed"）或百分数，统一收敛成 0~1 小数。"""

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
    if number > 1:
        number = number / 100.0 if number <= 100 else 1.0
    return round(max(0.0, min(1.0, number)), 2)


def _as_text(raw):
    """诊断用：把任意入参统一成可打印的文本。"""

    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, ensure_ascii=False)
    except Exception:
        return str(raw)


def _describe(name, raw):
    """打印一个入参的"体检报告"：长度、类型、顶层键、开头片段。

    平台没有单节点调试，这段日志就是定位"哪条线是空的"的唯一手段。
    """

    text = _as_text(raw)
    payload = _load(text, None)
    if not text:
        shape = "空值（上游未产出 / 引用绑错节点）"
    elif isinstance(payload, dict):
        shape = "dict 顶层键=%s" % list(payload.keys())[:8]
    elif isinstance(payload, list):
        shape = "list 长度=%d" % len(payload)
    else:
        shape = "非 JSON（%s）" % type(payload).__name__
    print("[去重验证分级][诊断] %s：字符数=%d / %s / 开头=%s"
          % (name, len(text), shape, text[:160].replace("\n", " ")))
    return text


def _http_get(url, timeout=VERIFY_TIMEOUT):
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read(500_000)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("gb18030", "ignore")
            return resp.status, text
    except Exception:
        return 0, ""


def _dedup_key(finding):
    """与上游约定一致的合并键：类型 + 规则 + 位置（跨页面聚合）。"""

    rule = _normalize_rule(finding)
    return hashlib.sha1("|".join([str(finding.get("type")), rule,
                                  _canonical_location(finding, rule)]).encode("utf-8")).hexdigest()[:16]


SECURITY_HEADER_NAMES = ("content-security-policy", "strict-transport-security",
                         "x-frame-options", "x-content-type-options", "referrer-policy")

# 各来源对同一个头的叫法不一样：被动线写响应头原名，能力集/nuclei 可能写中文或简称。
# 这里把别名收敛到统一规则名，位置也统一到响应头名，否则同一条风险会被两条线各报一次。
HEADER_ALIASES = (
    ("content-security-policy", ("csp", "内容安全策略")),
    ("strict-transport-security", ("hsts", "严格传输安全", "强制传输安全")),
    ("x-frame-options", ("点击劫持", "frame-options")),
    ("x-content-type-options", ("mime", "nosniff", "内容类型嗅探")),
    ("referrer-policy", ("referrer", "引用来源", "来源策略")),
)

RULE_ALIASES = (
    ("MISCONFIG.DIRECTORY_LISTING",
     ("目录列表", "目录浏览", "directory listing", "directory-listing", "index of")),
    ("MISCONFIG.SERVER_VERSION_LEAK",
     ("服务器版本", "version disclosure", "server 头", "server头", "软件版本泄露")),
    ("TAMPER.BASELINE_DIFF",
     ("篡改", "基线", "指纹变化", "页面被修改", "内容被修改", "hash 不一致", "hash不一致")),
    ("MALWARE.HIDDEN_LINK", ("暗链", "隐藏链接", "hidden link")),
    ("MALWARE.HIDDEN_IFRAME", ("隐藏框架", "隐藏 iframe", "hidden iframe")),
    ("MALWARE.INJECTED_SCRIPT", ("挂马", "注入脚本", "恶意脚本", "webshell", "网页后门")),
)

# 同一规则在不同来源下的"位置"写法也要统一，否则合并键仍然对不上
CANONICAL_LOCATIONS = {
    "MISCONFIG.SERVER_VERSION_LEAK": "server",
    "MISCONFIG.DIRECTORY_LISTING": "目录列表",
    "TAMPER.BASELINE_DIFF": "页面内容",
    "MALWARE.HIDDEN_LINK": "页面内容",
    "MALWARE.HIDDEN_IFRAME": "页面内容",
    "MALWARE.INJECTED_SCRIPT": "页面内容",
}

# TLS 类问题必须按子类分开：证书链不完整、自签名、证书过期、弱协议、弱套件
# 是五件不同的事，笼统归成一条会把真实问题并掉。
TLS_SUBTYPES = (
    ("SSL_TLS.CERT_CHAIN", ("证书链", "chain", "issuer", "中间证书")),
    ("SSL_TLS.SELF_SIGNED", ("自签名", "self-signed", "self signed", "selfsigned")),
    ("SSL_TLS.CERT_EXPIRING", ("即将过期", "过期", "expir")),
    ("SSL_TLS.WEAK_PROTOCOL", ("协议版本", "protocol", "sslv3", "ssl 3", "tls 1.0", "tls1.0",
                               "tls 1.1", "tls1.1", "已废弃")),
    ("SSL_TLS.WEAK_CIPHER", ("加密套件", "cipher", "弱加密")),
)


def _canonical_location(finding, rule):
    if rule.startswith("MISCONFIG.MISSING_HEADER."):
        return rule.rsplit(".", 1)[-1]
    if rule in CANONICAL_LOCATIONS:
        return CANONICAL_LOCATIONS[rule]
    return str(finding.get("location") or "")


def _normalize_rule(finding):
    """跨来源规则归一化：工具线（如 nuclei 模板）与被动线报同一问题时，收敛到同一个规则标识。

    否则同一个"缺少安全响应头"会被两条线各报一次，去重合并不到一起。
    """

    rule_id = str(finding.get("rule_id", ""))
    text = ("%s %s %s" % (rule_id, finding.get("title", ""), finding.get("location", ""))).lower()
    flat = text.replace("-", "").replace("_", "").replace(" ", "")
    for name, aliases in HEADER_ALIASES:
        if name in text or name.replace("-", "") in flat:
            return "MISCONFIG.MISSING_HEADER.%s" % name
        for alias in aliases:
            if alias in text or alias.replace(" ", "") in flat:
                return "MISCONFIG.MISSING_HEADER.%s" % name
    for canonical, aliases in RULE_ALIASES:
        for alias in aliases:
            if alias in text or alias.replace(" ", "") in flat:
                return canonical
    # TLS 类：先判子类，判不出来才落到通用 TLS 规则，避免把不同问题并成一条
    if "ssl" in text or "tls" in text or "certificate" in text or "证书" in text:
        for canonical, aliases in TLS_SUBTYPES:
            for alias in aliases:
                if alias in text or alias.replace(" ", "") in flat:
                    return canonical
        return "MISCONFIG.TLS_CONFIG"
    return rule_id


def _parse_tool_findings(raw):
    """容错解析自规划节点（工具线）的输出：可能是包了壳的 JSON 数组、带代码块或带说明文字。"""

    if raw is None or raw == "":
        return []
    payload = _unwrap(raw, None)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("findings", "results", "result_key", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, str):
                parsed = _parse_tool_findings(value)
                if parsed:
                    return parsed
    if isinstance(raw, str):
        text = re.sub(r"```(?:json)?", "", raw)
        start, end = text.find("["), text.rfind("]")
        if 0 <= start < end:
            try:
                parsed = json.loads(text[start:end + 1])
                if isinstance(parsed, list):
                    return [item for item in parsed if isinstance(item, dict)]
            except Exception:
                pass
    return []


def _merge(findings):
    """跨页面聚合：同一规则命中多个页面时合并为一条，保留受影响 URL 列表。"""

    groups = {}
    for item in findings:
        groups.setdefault(_dedup_key(item), []).append(item)

    merged = []
    for items in groups.values():
        items.sort(key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "info"), 0.05), reverse=True)
        base = dict(items[0])
        urls = sorted({str(f.get("url", "")) for f in items if f.get("url")})
        evidence = []
        for item in items:
            raw_evidence = item.get("evidence", "")
            candidates = raw_evidence if isinstance(raw_evidence, (list, tuple)) else [raw_evidence]
            for candidate in candidates:
                text = str(candidate).strip()
                if text and text not in evidence:
                    evidence.append(text)
        base["url"] = urls[0] if urls else base.get("url", "")
        base["affected_urls"] = urls
        base["occurrences"] = len(urls)
        base["evidence"] = evidence[:3]
        base["tools"] = sorted({str(f.get("tool", "")) for f in items if f.get("tool")})
        # 同一条结论若被两条线都报过，就是"交叉印证"——这是去重关联最直观的产出
        sources = sorted({str(f.get("source_line") or "passive") for f in items})
        base["source_lines"] = sources
        base["source_line"] = "both" if len(sources) > 1 else sources[0]
        if len(sources) > 1:
            base["evidence"] = base["evidence"] + \
                ["两条独立来源同时命中（%s），交叉印证降低了误报可能" % "、".join(sources)]
        if len(urls) > 1:
            base["title"] = "%s（影响 %d 个页面）" % (
                re.sub(r"（影响 \d+ 个页面）$", "", str(base.get("title", ""))), len(urls))
        merged.append(base)
    return merged


def _risk_score(severity, confidence):
    sev = SEVERITY_WEIGHT.get(str(severity).lower(), 0.05)
    reach = 0.5 + 0.5 * REACHABILITY
    crit = 0.6 + 0.4 * ASSET_CRITICALITY
    conf = 0.5 + 0.5 * _safe_confidence(confidence, 0.5)
    return round(sev * reach * crit * conf, 4)


def _level(score):
    for name, threshold in LEVEL_THRESHOLDS:
        if score >= threshold:
            return name
    return "P3"


def _fetch_with_fallback(url, counters):
    """复采时同样支持 https 失败退回 http，保证确证结论准确。"""

    time.sleep(DELAY_PER_HOST)
    counters["requests"] += 1
    status, text = _http_get(url)
    if status == 0 and str(url).startswith("https://"):
        counters["requests"] += 1
        status, text = _http_get("http://" + str(url)[len("https://"):])
    return status, text


def _verify(finding, counters):
    """非破坏性二次确证：只读复采一次，确认命中是否仍然存在。"""

    url = finding.get("url") or (finding.get("affected_urls") or [""])[0]
    if not url:
        return None
    status, text = _fetch_with_fallback(url, counters)
    if status != 200:
        return None                                     # 页面取不到，保持原置信度
    ftype = str(finding.get("type"))
    if ftype == "vuln":
        return True                                     # 敏感文件仍可访问即确证
    hint = str(finding.get("verify_hint") or "")
    if hint:
        return hint in text                             # 命中片段仍在 → 确证；已消失 → 疑似修复
    if ftype in ("misconfig", "leak"):
        return True                                     # 确定性结论 / 资源仍可访问
    return None                                         # 其余无法复判


def _confirm(finding, counters, retry_on_miss=True):
    """只读复采确证。第一次没命中时再采一次——一次抖动不该把真问题判成假问题。

    返回 (状态, 说明)：confirmed / unverified / miss。
    """

    outcome = _verify(finding, counters)
    if outcome is None:
        return "unverified", ""
    if outcome is True:
        return "confirmed", ""
    if retry_on_miss:
        outcome = _verify(finding, counters)
        if outcome is True:
            return "confirmed", "首次复采未命中、二次复采命中（响应存在抖动），判定为确证"
    return "miss", ""


def _suppress_rules(raw):
    """解析白名单/抑制规则：给"已知例外、有意配置"这类误报一个出口。"""

    payload = _unwrap(raw, None)
    if isinstance(payload, list):
        rules = payload
    elif isinstance(payload, dict):
        rules = payload.get("rules") or payload.get("suppress") or []
    else:
        rules = []
    return [rule for rule in rules if isinstance(rule, dict)]


def _match_suppress(finding, rule):
    """规则里写了哪几个字段，就按哪几个字段做 AND 匹配；写空的字段不参与判断。"""

    rule_id = str(rule.get("rule_id") or "").strip()
    if rule_id:
        normalized = _normalize_rule(finding)
        if not (normalized.startswith(rule_id) or str(finding.get("rule_id", "")).startswith(rule_id)):
            return False
    url = str(rule.get("url") or "").strip()
    if url:
        haystack = " ".join([str(finding.get("url") or "")]
                            + [str(item) for item in (finding.get("affected_urls") or [])])
        if url not in haystack:
            return False
    title = str(rule.get("title_contains") or "").strip()
    if title and title not in str(finding.get("title") or ""):
        return False
    tool = str(rule.get("tool") or "").strip()
    if tool:
        tools = " ".join([str(finding.get("tool") or "")]
                         + [str(item) for item in (finding.get("tools") or [])])
        if tool not in tools:
            return False
    severities = rule.get("severity_in") or []
    if severities and str(finding.get("severity")) not in severities:
        return False
    return True


def handler(args: Args) -> dict:
    started = time.time()
    counters = {"requests": 0}
    try:
        main_text = _describe("findings_payload（应为 ⑤ 三类检测）", _input(args, "findings_payload"))
        tool_text = _describe("tool_findings_payload（应为 ⑤b 工具线，可空）",
                              _input(args, "tool_findings_payload"))
        data = _unwrap(main_text)
        if isinstance(data, list):                 # 上游直接给了数组也认
            data = {"findings": data}
        if not isinstance(data, dict):
            data = {}
        raw_findings = [item for item in (data.get("findings") or []) if isinstance(item, dict)]
        # 工具线（⑤b 自规划 + MCP）的结果并入同一条管线：先补齐必填字段，再统一去重
        tool_findings = _parse_tool_findings(tool_text)
        if tool_findings:
            for item in tool_findings:
                item.setdefault("tool", item.get("tool") or "mcp-tool")
                item.setdefault("tier", "T1")
                item.setdefault("severity", "medium")
                item["confidence"] = _safe_confidence(item.get("confidence"), 0.75)
                item.setdefault("verified", False)
                item.setdefault("location", item.get("location") or "-")
                item.setdefault("asset", item.get("asset") or "")
                item.setdefault("evidence", item.get("evidence") or "")
                item["source_line"] = "tool"        # 标记来源：工具线（⑤b + MCP）
            raw_findings = raw_findings + tool_findings
        if not raw_findings and tool_findings:
            print("[去重验证分级][诊断] 主线为空，改以工具线结果 %d 条继续" % len(tool_findings))
            raw_findings = list(tool_findings)
        if not raw_findings:
            return _fail("没有待处理的检测结果：findings_payload 未取到 ⑤ 的 findings。"
                         "请检查 ⑥ 的 findings_payload 是否仍引用 ⑤（插入 ⑤b 后容易被动改指向）")

        merged = _merge(raw_findings)
        merged.sort(key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "info"), 0.05), reverse=True)

        # 先按严重度粗排，再对前 N 条做二次确证（控制请求量）
        suppress_rules = _suppress_rules(_input(args, "suppress_payload"))
        for index, finding in enumerate(merged):
            confidence = _safe_confidence(finding.get("confidence"), 0.6)
            finding.setdefault("source_line", "passive")
            tool_line = str(finding.get("source_line")) == "tool"
            has_hint = bool(str(finding.get("verify_hint") or "").strip())
            matched = next((rule for rule in suppress_rules if _match_suppress(finding, rule)), None)
            if matched is not None:
                # 已知例外：不进报告正文，但保留在附录与审计日志里，保证可追溯
                finding["verified"] = False
                finding["status"] = "suppressed"
                finding["suppress_reason"] = str(matched.get("reason") or "命中白名单/抑制规则")
                finding["evidence"] = list(finding.get("evidence", [])) + \
                    ["已按白名单抑制：%s" % finding["suppress_reason"]]
            elif tool_line and not has_hint:
                # 工具线结论（如 sslscan 的证书链判断）用一次 GET 复采根本验不了，
                # 不能冒充"已确证"：保留置信度、状态标 unverified，把复测方式交出去
                finding["verified"] = False
                finding["status"] = "unverified"
                finding["evidence"] = list(finding.get("evidence", [])) + \
                    ["工具线结论（%s），未做独立复采确证，建议用同一工具复测后再定性" % finding.get("tool", "mcp")]
            elif index < MAX_VERIFY:
                status, note = _confirm(finding, counters, retry_on_miss=not tool_line)
                if status == "confirmed":
                    finding["verified"] = True
                    finding["status"] = "confirmed"
                    confidence = min(confidence + 0.15, 0.98)
                    if note:
                        finding["evidence"] = list(finding.get("evidence", [])) + [note]
                elif status == "miss":
                    if tool_line:
                        # 工具线结论大多是协议层判断（证书链、端口、TLS 套件），
                        # 用一次 HTML 复采本来就验证不了，不能因此判成"疑似已修复"并砍置信度
                        finding["verified"] = False
                        finding["status"] = "unverified"
                        finding["evidence"] = list(finding.get("evidence", [])) + \
                            ["工具线结论，HTML 复采无法验证（协议层问题不在页面文本里），需用同一工具复测后定性"]
                    else:
                        finding["verified"] = False
                        finding["status"] = "needs_review"
                        confidence = round(confidence * 0.5, 2)
                        finding["evidence"] = list(finding.get("evidence", [])) + \
                            ["两次复采均未命中，疑似已修复或误报，建议人工复核"]
                else:
                    finding["status"] = "unverified"
            else:
                finding["status"] = "unverified"
            finding["confidence"] = round(confidence, 2)
            finding["risk_score"] = _risk_score(finding.get("severity"), confidence)
            finding["level"] = _level(finding["risk_score"])
            finding["cwe"] = CWE_MAP.get(str(finding.get("type")), "")

        merged.sort(key=lambda f: f["risk_score"], reverse=True)
        for index, finding in enumerate(merged, 1):
            finding["id"] = "F-%03d" % index

        by_level = {}
        by_source = {}
        cross = 0
        suppressed_detail = []
        for item in merged:
            key = item.get("source_line", "passive")
            by_source[key] = by_source.get(key, 0) + 1
            if key == "both":
                cross += 1
            if str(item.get("status")) == "suppressed":
                suppressed_detail.append({"id": item.get("id"), "title": item.get("title"),
                                          "reason": item.get("suppress_reason", "")})
                continue
            by_level[item["level"]] = by_level.get(item["level"], 0) + 1
        stats = {
            "raw": len(raw_findings),
            "merged": len(merged),
            "verified": sum(1 for f in merged if f.get("verified")),
            "needs_review": sum(1 for f in merged if f.get("status") == "needs_review"),
            "by_level": by_level,
            "by_source": by_source,
            "cross_verified": cross,
            "reported": len(merged) - len(suppressed_detail),
            "suppressed": len(suppressed_detail),
            "suppressed_detail": suppressed_detail,
            "requests": counters["requests"],
            "seconds": round(time.time() - started, 2),
        }
        print("[去重验证分级] 原始命中 %d → 去重后 %d（压缩 %.0f%%）/ 确证 %d / 待复核 %d / %s"
              % (stats["raw"], stats["merged"],
                 100.0 * (stats["raw"] - stats["merged"]) / max(1, stats["raw"]),
                 stats["verified"], stats["needs_review"],
                 "、".join("%s %d" % (k, v) for k, v in sorted(by_level.items())) or "无"))
        print("[去重验证分级] 来源构成：被动检测线 %d 条（⑤）· 工具线 %d 条（⑤b + MCP）· "
              "两线交叉印证 %d 条（三者合计 = 去重后 %d）"
              % (by_source.get("passive", 0), by_source.get("tool", 0), cross, len(merged)))
        if suppress_rules:
            print("[去重验证分级] 白名单抑制 %d 条（规则 %d 条）：%s"
                  % (len(suppressed_detail), len(suppress_rules),
                     "、".join("%s %s" % (item["id"], item["reason"]) for item in suppressed_detail[:5])
                     or "无命中"))
        return {"result_key": json.dumps({"findings": merged, "stats": stats}, ensure_ascii=False)}
    except Exception as exc:
        return _fail("去重验证分级执行异常：%s" % exc)


def _fail(message):
    print("[去重验证分级] " + message)
    return {"result_key": json.dumps({"findings": [], "stats": {"error": message}},
                                     ensure_ascii=False)}
