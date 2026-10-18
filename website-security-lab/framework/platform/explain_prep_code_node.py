# coding=utf-8
"""⑥b 代码节点 · 解释负载裁剪（⑥ 与 ⑦ 之间的节流阀）。

为什么需要它
------------
⑦ 是模型节点，它的输出长度 ≈ 风险条数 × 每条要写的字段。加了工具线（Nuclei 等）之后，
⑥ 交出来的条目会明显变多、证据变长，模型写出合法 JSON 的难度随之上升；
一旦超长或被截断，平台的输出校验会反复重试，界面上就是"一直运行中"。

做法：只把模型真正需要的字段喂给它，并按风险分截断条数。
    1) 字段瘦身：去掉 affected_urls / tools / source_lines / risk_score 等渲染用字段；
    2) 证据截断：每条证据最多 EVIDENCE_MAX 字，避免长响应体把上下文撑爆；
    3) 条数封顶：只送风险最高的 MAX_ITEMS 条，其余由 ⑧ 的内置模型/模板兜底补齐。

输入：
    findings_payload   ⑥ 去重验证分级的 result_key

输出（result_key，JSON 字符串）：
    [{"id","type","rule_id","title","severity","level","location","url","cwe",
      "tool","evidence","verify_hint"}, ...]
"""

from runtime import Args

import json

# ------------------------- 可调参数 -------------------------
MAX_ITEMS = 12          # 交给模型解释的条数上限（与 ⑧ 的内置模型单批条数保持一致）
EVIDENCE_MAX = 160      # 单条证据保留的最大字符数
# -----------------------------------------------------------

KEEP_KEYS = ("id", "type", "rule_id", "title", "severity", "level",
             "location", "url", "asset", "cwe", "tool", "verify_hint")


def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


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
    return payload if payload is not None else (default if default is not None else {})


def _evidence_text(item, limit=EVIDENCE_MAX):
    evidence = item.get("evidence", "")
    if isinstance(evidence, (list, tuple)):
        evidence = "；".join(str(part) for part in evidence if str(part).strip())
    text = str(evidence).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def handler(args: Args) -> dict:
    data = _unwrap(_input(args, "findings_payload"), {})
    if isinstance(data, list):
        findings = [item for item in data if isinstance(item, dict)]
    elif isinstance(data, dict):
        findings = [item for item in (data.get("findings") or []) if isinstance(item, dict)]
    else:
        findings = []

    ordered = sorted(findings, key=lambda f: float(f.get("risk_score") or 0), reverse=True)
    selected = ordered[:MAX_ITEMS]
    payload = []
    for item in selected:
        compact = {key: item[key] for key in KEEP_KEYS if item.get(key) not in (None, "")}
        compact["evidence"] = _evidence_text(item)
        payload.append(compact)

    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    print("[解释负载裁剪] 入参风险 %d 条 → 送模型 %d 条（其余由 ⑧ 兜底补齐）/ 负载 %d 字"
          % (len(findings), len(payload), len(text)))
    if len(findings) > MAX_ITEMS:
        print("[解释负载裁剪] 未送模型的条目：%s"
              % "、".join(str(item.get("id")) for item in ordered[MAX_ITEMS:]))
    return {"result_key": text}
