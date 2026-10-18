# coding=utf-8
# 3a 代码节点 · 授权闸门（快速判断，未授权直接终止）
#
# 输入参数（1 行）：auth_confirmed  ← 引用 2a_交互_授权确认 的 auth_confirmed
# 输出参数（只留 1 行）：result_key
#   值只有两种："OK" 或 "DENIED" —— 供两条边的「跳转条件」精确匹配
#
# 用法：两条边
#   3a → 2b_交互_巡检参数    跳转条件：result_key == 'OK'
#   3a → 结束节点            跳转条件：result_key == 'DENIED'
#   两条边的「是否并发执行」都必须关掉
from runtime import Args

import json

CONFIRM_WORD = "已获书面授权"
DENY_WORDS = ("暂无授权", "暂不扫描", "未获", "没有授权")


def _text(value):
    """交互节点的答案可能是 {_question,_answer,_options} / {A:…} / 纯字符串，统一取文本。"""

    if isinstance(value, dict):
        if "_answer" in value:
            return _text(value["_answer"])
        return "、".join(part for part in (_text(item) for item in value.values()) if part)
    if isinstance(value, (list, tuple)):
        return "、".join(part for part in (_text(item) for item in value) if part)
    return "" if value is None else str(value)


def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def handler(args: Args) -> dict:
    confirmed = _text(_input(args, "auth_confirmed"))
    denied = ((not confirmed)
              or any(word in confirmed for word in DENY_WORDS)
              or CONFIRM_WORD not in confirmed)
    if denied:
        message = "授权确认未通过（%s），已终止执行，未发起任何请求。" % (confirmed or "未选择")
        print("[授权闸门] DENIED - %s" % message)
        return {"result_key": "DENIED"}
    print("[授权闸门] OK - 授权确认通过（%s），继续采集巡检参数。" % confirmed)
    return {"result_key": "OK"}
