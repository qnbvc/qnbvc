"""本地验证探针节点：三种典型入参（正常 JSON / 包了壳 / 空值 / 纯文本）都要能读出形状。"""

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
    return module, Args


def main():
    probe, Args = load("probe_code_node")

    cases = [
        ("正常 JSON", json.dumps({"findings": [{"id": "F-001", "type": "misconfig"}], "stats": {}},
                              ensure_ascii=False)),
        ("包了壳", json.dumps({"result_key": json.dumps([{"id": "F-001"}])}, ensure_ascii=False)),
        ("纯文本", "未发现风险，工具执行正常。"),
        ("空值", ""),
    ]
    for label, value in cases:
        args = Args()
        args.input = types.SimpleNamespace(probe=value)
        out = probe.handler(args)["result_key"]
        print("-" * 70)
        print("用例：%s" % label)
        print(out)

    # 结构透视：模拟能力集返回的形态（对象 + 多个数组 + 文字字段）
    shape = {
        "site_id": "demo-local",
        "findings": [{"id": "SENS-003", "title": "数据库备份可下载", "severity": "严重",
                      "confidence": "confirmed", "url": "/backup/db.sql"}],
        "checks": [{"name": "未发现登录页隐藏 GET 参数", "effect": "positive"}],
        "blocked": [],
        "errors": [],
    }
    shape_args = Args()
    shape_args.input = types.SimpleNamespace(probe=json.dumps(shape, ensure_ascii=False))
    print("=" * 70)
    print("结构透视输出：")
    print(probe.handler(shape_args)["result_key"])


if __name__ == "__main__":
    main()
