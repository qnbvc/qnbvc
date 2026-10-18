# coding=utf-8
"""④b 代码节点 · 自规划节点输入裁剪（把"页面全量"压成"任务简报"）。

为什么要它
----------
④ 资产发现的输出里，每个页面都带着完整响应头、标题、内容片段、资源列表，
10 个页面就能到几十 KB。平台会因为超出展示上限把它落成文件，
节点输出面板只显示"内容超长，暂不支持查看"——更关键的是，
自规划节点要把这份 JSON 塞进模型上下文，输入越大越容易变慢、空转甚至卡死。

做法：只把"工具编排真正需要的"喂给模型——
    目标主机清单 + URL 清单（有上限）+ 授权边界摘要 + 敏感规则摘要，
    页面正文、响应头、资源列表、统计字段一律不带。

输入：
    pages_payload   ④ 代码_资产与页面发现的 result_key
    gate_payload    ③ 代码_策略校验与上下文构建的 result_key（可选，用于补边界摘要）

输出（result_key，JSON 字符串）：
    {"targets": [...], "urls": [...], "url_count": N, "scope": {...}, "sensitive": {...}}
"""

from runtime import Args

import json
import re

# ------------------------- 可调参数 -------------------------
MAX_TARGETS = 10        # 最多保留多少个目标主机
MAX_URLS = 40           # 最多保留多少个 URL
MAX_KEYWORDS = 30       # 敏感关键词最多带几个
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
    payload = raw
    for _ in range(4):
        if isinstance(payload, str):
            parsed = _load(payload, None)
            if parsed is None:
                return default if default is not None else {}
            payload = parsed
            continue
        if isinstance(payload, dict) and "result_key" in payload:
            payload = payload["result_key"]
            continue
        break
    return payload if isinstance(payload, (dict, list)) else (default if default is not None else {})


def _host_of(value):
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"(?i)^https?://([^/?#\s]+)", text)
    if match:
        return match.group(1).rstrip("/").lower()
    if re.match(r"^[A-Za-z0-9._-]+(:\d+)?$", text) and "." in text:
        return text.lower()
    return ""


def handler(args: Args) -> dict:
    pages_data = _unwrap(_input(args, "pages_payload"), {})
    if isinstance(pages_data, list):
        pages_data = {"pages": pages_data}
    pages = pages_data.get("pages") or []
    assets = pages_data.get("assets") or []
    stats = pages_data.get("stats") or {}

    targets, urls = [], []
    for page in pages:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url") or "").strip()
        host = _host_of(url)
        if host and host not in targets:
            targets.append(host)
        if url and url not in urls:
            urls.append(url)
    for asset in assets:
        host = _host_of(asset.get("host") if isinstance(asset, dict) else asset)
        if host and host not in targets:
            targets.append(host)

    gate = _unwrap(_input(args, "gate_payload"), {})
    snapshot = gate.get("scope_snapshot") if isinstance(gate, dict) else {}
    if isinstance(snapshot, str):
        snapshot = _load(snapshot, {})
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    rules = gate.get("sensitive_rules") if isinstance(gate, dict) else {}
    if isinstance(rules, str):
        rules = _load(rules, {})
    rules = rules if isinstance(rules, dict) else {}

    brief = {
        "targets": targets[:MAX_TARGETS],
        "urls": urls[:MAX_URLS],
        "url_count": len(urls),
        "scope": {
            "domains": (snapshot.get("exact_domains") or snapshot.get("domains") or [])[:MAX_TARGETS],
            "wildcard_domains": (snapshot.get("wildcard_domains") or [])[:5],
            "excluded_paths": ((snapshot.get("exclude") or {}).get("paths") or [])[:10],
            "rate_limit_qps": snapshot.get("rate_limit_qps") or snapshot.get("qps") or 3,
            "tier_notice": "默认只做只读检测（T0/T1）；主动验证（T2）默认关闭",
        },
        "sensitive": {
            "keywords": [str(item) for item in (rules.get("keywords") or [])[:MAX_KEYWORDS]],
            "file_types": [str(item) for item in (rules.get("file_types") or [])[:10]],
            "regex_count": len(rules.get("regex") or []),
        },
    }
    text = json.dumps(brief, ensure_ascii=False, separators=(",", ":"))
    raw_size = len(_as_text(_input(args, "pages_payload")))
    print("[输入裁剪] 页面 %s 个 → 目标 %d 个 / URL %d 条；%d 字 → %d 字（压缩 %.0f%%）"
          % (stats.get("pages", len(pages)), len(brief["targets"]), len(brief["urls"]),
             raw_size, len(text), 100.0 * (1 - len(text) / max(1, raw_size))))
    return {"result_key": text}


def _as_text(raw):
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, ensure_ascii=False)
    except Exception:
        return str(raw)
