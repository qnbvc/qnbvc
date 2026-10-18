"""一页都没抓到时的报告必须自曝其短，而不是写成"本周期未发现风险"。

用例 1：pages 为空 → 报告顶部出现"结果不可用"警告，运行数据出现"采集校验"行；
用例 2：pages 正常 → 不出现该警告（避免噪音）。
"""

import importlib.util
import json
import sys
import types
from pathlib import Path


def load(name):
    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if hasattr(module, "LLM_ENABLED"):
        module.LLM_ENABLED = False
    return module, Args


def build(Args, pages):
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": [], "stats": {"by_level": {}, "raw": 0,
                                                               "merged": 0}}, ensure_ascii=False),
        explain_payload="[]",
        discover_payload=json.dumps({"pages": pages, "blocked": [], "assets": []}, ensure_ascii=False),
        alert_channel="")
    return args


def main():
    report, Args = load("report_code_node")
    checks = []

    empty = report.handler(build(Args, []))["result_key"]
    checks.append(("用例 1（未采集到页面 → 报告自曝结果不可用）",
                   "本轮未采集到任何页面，报告结果不可用" in empty
                   and "采集校验：页面 0 个" in empty
                   and "site_id（如 demo-local）" in empty))

    normal = report.handler(build(Args, [{"url": "https://a.example/"}]))["result_key"]
    checks.append(("用例 2（正常采集时不出现该警告）",
                   "本轮未采集到任何页面" not in normal))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    for line in empty.splitlines():
        if "不可用" in line or line.startswith("采集校验"):
            print("   >", line.strip()[:110])


if __name__ == "__main__":
    main()
