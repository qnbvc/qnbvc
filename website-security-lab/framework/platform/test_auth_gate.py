r"""③a 授权闸门 —— 本地离线测试。

运行：在 website-security-lab 项目根目录下执行
      python framework\platform\test_auth_gate.py
"""

import importlib.util
import io
import sys
import types
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def load_node():
    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    path = Path(__file__).with_name("auth_gate_code_node.py")
    spec = importlib.util.spec_from_file_location("auth_gate_code_node", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, Args


def answer(value):
    """模拟单选：_answer 是 {A: 选中文本}。"""

    return {"_question": "q", "_answer": {"A": value}, "_options": {}}


def main():
    module, Args = load_node()
    cases = [
        ("✅ 已获书面授权（单选对象）", answer("✅ 已获书面授权"), "OK"),
        ("纯字符串 已获书面授权", "已获书面授权", "OK"),
        ("❌ 暂无授权（单选对象）", answer("❌ 暂无授权"), "DENIED"),
        ("🔍 仅了解功能，暂不扫描", answer("🔍 仅了解功能，暂不扫描"), "DENIED"),
        ("空值（未选择）", "", "DENIED"),
        ("乱七八糟的回答", "随便写的", "DENIED"),
    ]
    ok = 0
    print("=" * 70)
    for title, value, expect in cases:
        args = Args()
        args.input = types.SimpleNamespace(auth_confirmed=value)
        got = module.handler(args)["result_key"]
        passed = got == expect
        ok += 1 if passed else 0
        print("%s %-28s 期望=%-7s 实际=%s" % ("[通过]" if passed else "[失败]", title, expect, got))
    print("=" * 70)
    print("结果：%d/%d 通过" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
