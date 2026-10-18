# coding=utf-8
"""探针节点（临时排障用，不参与正式流程）。

平台没有单节点调试，所以想看清某个节点的输出到底是什么形状，最省事的办法是：
在它后面挂一个探针节点，跑一次全流程，看探针的运行结果。

用法：
1) 给本节点加输入参数 probe，引用你要观察的那个节点的输出；想同时看多个再加 probe2 / probe3。
2) 上一个节点连到本节点，本节点连回原来的下一个节点。
3) 跑完看本节点运行结果：每个入参的长度、类型、顶层键、开头 200 字。
4) 排完障把本节点从画布上摘掉。

输出全是文本，不改变任何上游数据，可以安全地插在任意位置。
"""

from runtime import Args

import json

MAX_PREVIEW = 200


def _params(args):
    inp = getattr(args, "input", None)
    if inp is None:
        return {}
    if isinstance(inp, dict):
        return inp
    return {name: getattr(inp, name, None) for name in dir(inp) if not name.startswith("_")}


def _to_text(raw):
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, ensure_ascii=False)
    except Exception:
        return str(raw)


def _peek(raw):
    text = _to_text(raw)
    payload = None
    if text:
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
    if isinstance(payload, dict):
        shape = "JSON 对象，顶层键 %s" % list(payload.keys())[:10]
    elif isinstance(payload, list):
        keys = sorted({k for item in payload if isinstance(item, dict) for k in item})[:10] if payload else []
        shape = "JSON 数组，元素 %d 个，元素字段 %s" % (len(payload), keys)
    elif text == "":
        shape = "空值（上游没产出，或引用绑错了节点）"
    else:
        shape = "纯文本（不是 JSON，下游代码节点会解析失败）"
    return text, shape


def _unwrap(raw):
    """剥掉平台引用时包的 {"result_key": ...} 外壳，拿到真正的结构体。"""

    payload = raw
    for _ in range(4):
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return None
            continue
        if isinstance(payload, dict) and "result_key" in payload and len(payload) <= 3:
            payload = payload["result_key"]
            continue
        break
    return payload


def _schema(raw):
    """把上游输出的"骨架"打印出来：顶层键、每个数组有几项、元素有哪些字段、首项长什么样。

    接外部能力集时最费时间的就是这一步——不看清骨架，只能一个字段一个字段地崩。
    """

    payload = _unwrap(raw)
    if isinstance(payload, dict):
        lines = ["JSON 对象，顶层键：%s" % list(payload.keys())[:15]]
        for key, value in list(payload.items())[:15]:
            if isinstance(value, list):
                fields = sorted({k for item in value if isinstance(item, dict) for k in item})
                lines.append("  · %s：数组 %d 项；元素字段 %s" % (key, len(value), fields[:20]))
                if value:
                    lines.append("      首项：%s" % json.dumps(value[0], ensure_ascii=False)[:260])
            elif isinstance(value, dict):
                lines.append("  · %s：对象，键 %s" % (key, list(value.keys())[:12]))
            elif isinstance(value, str) and len(value) > 60:
                lines.append("  · %s：文本 %d 字，开头 %s" % (key, len(value), value[:60]))
            else:
                lines.append("  · %s：%s" % (key, value))
        return lines
    if isinstance(payload, list):
        fields = sorted({k for item in payload if isinstance(item, dict) for k in item})
        lines = ["JSON 数组 %d 项；元素字段 %s" % (len(payload), fields[:20])]
        if payload:
            lines.append("  首项：%s" % json.dumps(payload[0], ensure_ascii=False)[:260])
        return lines
    text = _to_text(raw)
    return ["非 JSON 文本 %d 字，开头：%s" % (len(text), text[:300].replace("\n", " "))]


def handler(args: Args) -> dict:
    params = _params(args)
    names = [name for name in ("probe", "probe2", "probe3") if name in params]
    if not names:
        names = [name for name in params if str(name).startswith("probe")]
    lines = []
    for name in names:
        text, shape = _peek(params.get(name))
        lines.append("【%s】字符数 %d，%s" % (name, len(text), shape))
        if text:
            preview = text[:MAX_PREVIEW].replace("\n", " ")
            lines.append("    开头：%s%s" % (preview, " ..." if len(text) > MAX_PREVIEW else ""))
        for line in _schema(params.get(name)):        # 结构透视：字段名与首项样本
            lines.append("    " + line)
    if not lines:
        lines.append("未取到 probe 入参：请在节点入参里添加 probe 并引用上游节点输出")
    report = "\n".join(lines)
    print("[探针] " + report.replace("\n", "\n[探针] "))
    return {"result_key": report}
