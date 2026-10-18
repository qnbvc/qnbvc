"""复现线上崩溃：能力集返回的 confidence 是文字 `confirmed`，节点整个挂掉。

用例 1：⑤c 收到 confidence="confirmed" 不崩，并转成数值；
用例 2：confidence 是百分数（95）时收敛成 0.95；
用例 3：⑥ 直接收到文字置信度也不崩（防御性解析）；
用例 4：能力集列的"没问题的检查项"（effect=positive）不被当成风险。
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
    if hasattr(module, "DELAY_PER_HOST"):
        module.DELAY_PER_HOST = 0.02
    return module, Args


MCP_ITEMS = [
    {"id": "SENS-003", "category": "敏感信息", "title": "数据库备份可下载",
     "severity": "严重", "confidence": "confirmed", "url": "http://127.0.0.1:8899/backup/db.sql",
     "evidence": "GET /backup/db.sql → 200"},
    {"id": "CONF-006", "category": "配置缺陷", "title": "目录浏览",
     "severity": "中", "confidence": 95, "url": "http://127.0.0.1:8899/backup/",
     "evidence": "返回 Index of /backup"},
    {"id": "CHK-002", "title": "未发现登录页隐藏 GET 参数", "effect": "positive",
     "mitigates": "基于隐藏 GET 参数的扩大攻击面", "confidence": "confirmed"},
]


def main():
    norm, Args = load("tool_norm_code_node")
    dedup, _ = load("dedup_code_node")
    checks = []

    args = Args()
    args.input = types.SimpleNamespace(
        tool_payload="",
        mcp_payload=json.dumps({"findings": MCP_ITEMS}, ensure_ascii=False),
        scope_payload=json.dumps({"scope_snapshot": json.dumps({"active_assets": ["127.0.0.1:8899"]})},
                                 ensure_ascii=False))
    out = json.loads(norm.handler(args)["result_key"])
    by_id = {item["external_id"]: item for item in out["findings"]}

    checks.append(("用例 1（文字置信度不崩且转成数值）",
                   by_id["SENS-003"]["confidence"] == 0.9))
    checks.append(("用例 2（百分数收敛为小数）",
                   by_id["CONF-006"]["confidence"] == 0.95))
    checks.append(("用例 4（positive 检查项不算风险）",
                   "CHK-002" not in by_id and len(out["findings"]) == 2))

    # ⑥ 直接吃文字置信度也不能崩
    dedup_args = Args()
    dedup_args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": [{"asset": "a", "url": "http://a/", "type": "leak",
                                                   "rule_id": "X", "title": "T", "severity": "high",
                                                   "evidence": "e", "confidence": "confirmed"}],
                                     "stats": {}}, ensure_ascii=False),
        tool_findings_payload="",
        suppress_payload="")
    result = json.loads(dedup.handler(dedup_args)["result_key"])
    checks.append(("用例 3（⑥ 面对文字置信度不崩）",
                   len(result["findings"]) == 1 and result["findings"][0]["confidence"] >= 0.6))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    for item in out["findings"]:
        print("   > [%s|%s] 置信度=%s %s" % (item["type"], item["severity"], item["confidence"],
                                             item["title"]))


if __name__ == "__main__":
    main()
