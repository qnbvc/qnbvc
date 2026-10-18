# coding=utf-8
"""⑤ 代码节点 · 三类检测（敏感信息泄露 / 弱配置 / 暴露面 / 挂马特征）。

输入：
    pages_payload     ④ 资产发现的 result_key（JSON 字符串）
    rules_payload     ③ 合规闸门的 result_key（取里面的 sensitive_rules）
    baseline_payload  可选：上一轮的基线快照；为空则跳过篡改比对

输出（result_key，JSON 字符串）：
    {
      "findings": [{"asset","url","type","rule_id","title","severity","tool","tier",
                    "location","evidence","verify_hint","confidence","verified"}],
      "stats":    {"pages","findings","by_type","requests","seconds"},
      "skipped":  [{"check","reason"}]
    }

设计要点：
    1. 全部为确定性规则（关键词/正则/响应头/特征串），不依赖模型判断，误报可控；
    2. 命中结果自动脱敏后再进证据字段；
    3. 暴露面探测属 T1 受控档：只探 active_assets 里显式授权的资产，其余跳过并记 skipped；
    4. 只发 GET、限速、带自定义 UA；不做任何写操作。
"""

from runtime import Args

import json
import re
import time
import urllib.error
import urllib.request

# ------------------------- 可调参数 -------------------------
SECURITY_HEADERS = (
    ("content-security-policy", "CSP 缺失", "medium"),
    ("x-frame-options", "点击劫持防护头缺失", "low"),
    ("strict-transport-security", "HSTS 缺失", "medium"),
    ("x-content-type-options", "MIME 嗅探防护头缺失", "low"),
    ("referrer-policy", "Referrer-Policy 缺失", "info"),
)

# 挂马 / 暗链特征（确定性正则，命中即可疑，仍需人工复核）
OBFUSCATION_PATTERNS = (
    ("MALWARE.EVAL_DECODE_CHAIN",
     r"eval\s*\(\s*(unescape|atob|String\.fromCharCode)",
     "混淆脚本：eval + 解码链", "critical"),
    ("MALWARE.DOCUMENT_WRITE_UNESCAPE",
     r"document\.write\s*\(\s*unescape",
     "混淆脚本：document.write(unescape(...))", "high"),
    ("MALWARE.HIDDEN_IFRAME",
     r"<iframe[^>]*(width\s*=\s*[\"']?0|height\s*=\s*[\"']?0)",
     "隐藏 iframe（0 尺寸）", "high"),
    ("MALWARE.HIDDEN_LINK",
     r"<a\b[^>]*style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0)",
     "隐藏链接（暗链特征）", "high"),
    ("MALWARE.INSECURE_EXTERNAL_SCRIPT",
     r"<script[^>]+src\s*=\s*[\"']http://",
     "HTTPS 页面引入 HTTP 外部脚本", "high"),
)

# T1 受控探测：常见敏感文件与调试端点
EXPOSURE_PATHS = ("/backup.zip", "/config/database.yml", "/.env", "/phpinfo.php", "/.git/config")

DEFAULT_FILE_TYPES = ("pdf", "docx", "xlsx", "csv", "sql", "bak", "env", "log")
REQUEST_TIMEOUT = 8
DELAY_PER_HOST = 0.3
USER_AGENT = "SecurityInspector/1.0 (+authorized-scan; contact=secops@example.gov.cn)"
# -----------------------------------------------------------


# ------------------------------ 取值与工具 ------------------------------

def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def _load(raw, default=None):
    """兼容"JSON 字符串 / 字典"两种输入形态。"""

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


def _mask(value):
    """证据脱敏：只保留首尾少量字符。"""

    value = str(value)
    if len(value) <= 6:
        return value[:1] + "*" * max(0, len(value) - 2) + value[-1:]
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def _http_get(url, timeout=REQUEST_TIMEOUT):
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read(200_000)
            return resp.status, len(raw), resp.geturl()
    except urllib.error.HTTPError as exc:
        return exc.code, 0, url
    except Exception:
        return 0, 0, url


# ------------------------------ 检测逻辑 ------------------------------

def _add(findings, seen, asset, url, ftype, rule_id, title, severity, tool, tier,
         location, evidence, verify_hint="", confidence=0.8):
    key = "|".join([url, ftype, rule_id, location])
    if key in seen:
        return
    seen.add(key)
    findings.append({
        "asset": asset, "url": url, "type": ftype, "rule_id": rule_id, "title": title,
        "severity": severity, "tool": tool, "tier": tier, "location": location,
        "evidence": evidence, "verify_hint": verify_hint,
        "confidence": confidence, "verified": False,
    })


def _scan_leak(page, ruleset, asset, findings, seen):
    """敏感信息泄露：关键词 / 正则 / 文件类型（含白名单过滤与脱敏）。"""

    text = page.get("text", "") or ""
    url = page["url"]
    whitelist = [str(w) for w in ruleset.get("whitelist", []) if w]

    def whitelisted(value):
        return any(w and (w in value or value in w) for w in whitelist)

    for keyword in ruleset.get("keywords", []):
        keyword = str(keyword)
        if keyword and keyword in text and not whitelisted(keyword):
            _add(findings, seen, asset, url, "leak", "LEAK.KEYWORD.%s" % keyword,
                 "命中自定义敏感关键词：%s" % keyword, "high", "sensitive-scan", "T0",
                 "页面内容", "命中关键词（已脱敏）：%s" % _mask(keyword), keyword)

    for rule in ruleset.get("regex", []):
        name, pattern = str(rule.get("name", "未命名")), str(rule.get("pattern", ""))
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        # 逐个匹配检查：不能只看第一处命中，否则第一处落在白名单会漏掉后面真正的问题
        matched = None
        for candidate in list(compiled.finditer(text))[:50]:
            if not whitelisted(candidate.group(0)):
                matched = candidate
                break
        if matched:
            _add(findings, seen, asset, url, "leak", "LEAK.REGEX.%s" % name,
                 "命中敏感信息规则：%s" % name, "high", "sensitive-scan", "T0",
                 "页面内容", "命中值（已脱敏）：%s" % _mask(matched.group(0)),
                 matched.group(0), 0.85)

    file_types = [str(t).lower().lstrip(".") for t in ruleset.get("file_types", [])] or list(DEFAULT_FILE_TYPES)
    path = url.split("?")[0]
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext and ext in file_types:
        _add(findings, seen, asset, url, "leak", "LEAK.FILE_TYPE.%s" % ext,
             "敏感文件类型可公开访问：.%s" % ext, "medium", "sensitive-scan", "T0",
             "文件下载", "该资源（.%s）可被匿名下载" % ext, "")


def _scan_misconfig(page, asset, findings, seen):
    """弱配置：安全响应头缺失与服务器版本泄露。"""

    headers = {k.lower(): v for k, v in (page.get("headers") or {}).items()}
    url = page["url"]
    for name, desc, severity in SECURITY_HEADERS:
        if name not in headers:
            _add(findings, seen, asset, url, "misconfig",
                 "MISCONFIG.MISSING_HEADER.%s" % name,
                 "%s：%s" % (desc, name), severity, "headers-baseline", "T0",
                 name, "响应头中未出现 %s" % name)
    server = str(headers.get("server", ""))
    if re.search(r"\d+\.\d+", server):
        _add(findings, seen, asset, url, "misconfig", "MISCONFIG.SERVER_VERSION_LEAK",
             "响应头泄露服务器版本", "low", "headers-baseline", "T0",
             "server", "Server: %s" % _mask(server))


def _scan_malware(page, asset, findings, seen):
    """挂马 / 暗链特征：混淆脚本、隐藏 iframe、隐藏链接、不安全外部脚本。"""

    text = page.get("text", "") or ""
    url = page["url"]
    for rule_id, pattern, title, severity in OBFUSCATION_PATTERNS:
        matched = re.search(pattern, text, re.I)
        if matched:
            _add(findings, seen, asset, url, "malware", rule_id, title, severity,
                 "malware-signature", "T0", "HTML 源码",
                 "命中片段：%s" % matched.group(0)[:80], matched.group(0)[:60], 0.65)


def _scan_exposure(active_assets, findings, seen, skipped, counters):
    """暴露面探测（T1 受控档）：只探显式授权的资产。"""

    if not active_assets:
        skipped.append({"check": "vuln",
                        "reason": "没有资产获得 T1 受控探测授权，跳过暴露面探测"})
        return
    for asset in active_assets:
        base = str(asset)
        for path in EXPOSURE_PATHS:
            time.sleep(DELAY_PER_HOST)                       # 限速
            counters["requests"] += 1
            status, size, final_url = _http_get("https://%s%s" % (base, path))
            if status == 0:                                  # https 不可用时退回 http
                counters["requests"] += 1
                status, size, final_url = _http_get("http://%s%s" % (base, path))
            if status != 200 or size <= 0:
                continue
            rule = path.strip("/").replace("/", "_").replace(".", "_").upper()
            _add(findings, seen, base, "https://%s%s" % (base, path), "vuln",
                 "EXPOSURE.SENSITIVE_FILE.%s" % rule,
                 "敏感文件可公开访问：%s" % path, "critical", "exposure-probe", "T1",
                 path, "GET %s → HTTP 200，返回 %d 字节" % (path, size), path, 0.9)


# ------------------------------- 主逻辑 -------------------------------

def handler(args: Args) -> dict:
    started = time.time()
    findings, seen, skipped = [], set(), []
    counters = {"requests": 0}
    try:
        pages_data = _unwrap(_input(args, "pages_payload"))
        gate = _unwrap(_input(args, "rules_payload"))
        baseline = _unwrap(_input(args, "baseline_payload"))
        ruleset = _load(gate.get("sensitive_rules", "{}"), {})
        snapshot = _load(gate.get("scope_snapshot", "{}"), {})

        pages = pages_data.get("pages", []) or []
        if not pages:
            return _fail("没有可检测的页面：请确认 ④ 资产发现已成功返回 pages")

        for page in pages:
            asset = str(page.get("url", "")).split("//")[-1].split("/")[0]
            _scan_leak(page, ruleset, asset, findings, seen)
            _scan_misconfig(page, asset, findings, seen)
            _scan_malware(page, asset, findings, seen)

        _scan_exposure(snapshot.get("active_assets", []) or [], findings, seen,
                       skipped, counters)

        if not baseline:
            skipped.append({"check": "tamper",
                            "reason": "无基线快照，本轮跳过页面篡改比对（第二轮巡检才会产出）"})

        by_type = {}
        for item in findings:
            by_type[item["type"]] = by_type.get(item["type"], 0) + 1
        result = {
            "findings": findings,
            "stats": {"pages": len(pages), "findings": len(findings), "by_type": by_type,
                      "requests": counters["requests"],
                      "seconds": round(time.time() - started, 2)},
            "skipped": skipped,
        }
        print("[三类检测] 页面 %d 个 → 命中 %d 条（%s）/ 探测请求 %d 次 / 跳过 %d 项（%.1fs）"
              % (len(pages), len(findings),
                 "、".join("%s %d" % (k, v) for k, v in by_type.items()) or "无",
                 counters["requests"], len(skipped), time.time() - started))
        return {"result_key": json.dumps(result, ensure_ascii=False)}
    except Exception as exc:
        return _fail("三类检测执行异常：%s" % exc)


def _fail(message):
    print("[三类检测] " + message)
    return {"result_key": json.dumps(
        {"findings": [], "stats": {}, "skipped": [{"check": "all", "reason": message}]},
        ensure_ascii=False)}
