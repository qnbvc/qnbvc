"""本地验证脚本：给平台代码节点做一次离线自测（模拟 runtime.Args）。

运行： python framework/platform/test_gate_node.py
"""

import importlib.util
import json
import sys
import types
from pathlib import Path


def load_handler():
    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    path = Path(__file__).with_name("gate_code_node.py")
    spec = importlib.util.spec_from_file_location("gate_code_node", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.handler, Args


def run_case(title, **fields):
    handler, Args = load_handler()
    args = Args()
    args.input = types.SimpleNamespace(**fields)
    result = handler(args)
    print("=" * 72)
    print(title, "→ valid =", result["valid"])
    print("summary :", result["summary"])
    errors = json.loads(result["errors"])
    warnings = json.loads(result["warnings"])
    for item in errors:
        print("  [ERROR]", item["code"], item["field"], "-", item["message"])
    for item in warnings:
        print("  [WARN ]", item["code"], item["field"], "-", item["message"])
    return result


if __name__ == "__main__":
    good = run_case(
        "用例1 正常配置",
        auth_targets="portal.example.gov.cn, *.example.gov.cn, 203.0.113.0/24",
        scope_exclude="/admin/export, api/personal/*",
        schedule="每天 02:00 巡检，仅 02:00-05:00 发请求",
        sensitive_keywords="内部资料, 仅供内部使用",
        sensitive_regex=r"(?<!\d)1[3-9]\d{9}(?!\d); \d{17}[\dXx]",
    )
    print("scope_snapshot:", json.dumps(json.loads(good["scope_snapshot"]), ensure_ascii=False)[:400])

    run_case(
        "用例2 裸通配 + 坏正则",
        auth_targets="*",
        scope_exclude="无",
        schedule="每天巡检",
        sensitive_keywords="的",
        sensitive_regex="([0-9",
    )

    run_case(
        "用例3 只给一个时间点",
        auth_targets="portal.example.gov.cn",
        scope_exclude="无",
        schedule="每天凌晨 3 点巡检",
        sensitive_keywords="内部资料",
        sensitive_regex="",
    )

    run_case("用例4 全空输入", auth_targets="", scope_exclude="", schedule="",
             sensitive_keywords="", sensitive_regex="")
