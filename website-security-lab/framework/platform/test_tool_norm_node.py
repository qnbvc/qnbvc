"""验证 ⑤c 工具线规范化节点：四种典型 ⑤b 输出都要能正确处理。"""

import importlib.util
import json
import sys
import types
from pathlib import Path

# 用户平台上 ⑤b 的真实输出（散文，含证书分析，没有 JSON）
PROSE = ("非常好！现在我有了完整的证书信息。让我分析一下：  **证书信息：** "
         "- 颁发者：Let's Encrypt (YE2) - 可信 CA - 主体：fangxiangji.gymjilv.cn "
         "- 生效日期：2026-09-20 - 过期日期：2026-12-19 - 当前日期：2026-10-15  "
         "**证书有效期**：还有约 2 个月，正常。**结论**：未发现 TLS 配置问题。")

PROSE_WITH_JSON = PROSE + """
整理成标准输出如下：
```json
[
  {"asset": "fangxiangji.gymjilv.cn", "url": "https://fangxiangji.gymjilv.cn/",
   "type": "misconfig", "rule_id": "SSL_TLS.WEAK_PROTOCOL", "title": "TLS 1.0 仍然启用",
   "severity": "high", "tool": "SSL TLS检测", "tier": "T1", "location": "TLS 配置",
   "evidence": "sslscan 显示 TLS 1.0 握手成功"}
]
```
以上。
"""

BARE_ARRAY = [{"rule_id": "SSL_TLS.CERT_EXPIRING", "title": "证书 30 天内到期",
               "severity": "MEDIUM", "evidence": "证书 2026-11-01 到期", "confidence": 0.9}]

SCOPE = {"result_key": json.dumps({"valid": 1, "scope_snapshot": json.dumps(
    {"active_assets": ["fangxiangji.gymjilv.cn"], "domains": ["gymjilv.cn"]})}, ensure_ascii=False)}

# 目标一致性闸门：测试载荷里的 host 必须落在授权目标内，否则会被整条隔离
SCOPE_RANGE = {"result_key": json.dumps({"valid": 1, "scope_snapshot": json.dumps(
    {"active_assets": ["127.0.0.1:8899"], "domains": ["127.0.0.1:8899"]})}, ensure_ascii=False)}


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


def run(norm, Args, payload, scope=SCOPE, payload_name="tool_payload", payload_value=None):
    args = Args()
    args.input = types.SimpleNamespace(**{"tool_payload": payload, "mcp_payload": "",
                                          "scope_payload": scope,
                                          payload_name: payload_value if payload_value is not None else payload})
    return json.loads(norm.handler(args)["result_key"])


def main():
    norm, Args = load("tool_norm_code_node")
    checks = []

    out = run(norm, Args, PROSE)
    checks.append(("用例 1（纯散文 → 不猜、输出空数组）",
                   out["findings"] == [] and "没有找到 JSON 数组" in out["note"]))

    out = run(norm, Args, PROSE_WITH_JSON)
    checks.append(("用例 2（散文里的 JSON 代码块被抠出）",
                   len(out["findings"]) == 1
                   and out["findings"][0]["rule_id"] == "SSL_TLS.WEAK_PROTOCOL"
                   and out["findings"][0]["severity"] == "high"))

    out = run(norm, Args, json.dumps({"result_key": json.dumps(BARE_ARRAY, ensure_ascii=False)},
                                     ensure_ascii=False))
    item = out["findings"][0] if out["findings"] else {}
    checks.append(("用例 3（平台包壳 + 缺字段补齐）",
                   item.get("severity") == "medium"
                   and item.get("asset") == "fangxiangji.gymjilv.cn"
                   and item.get("url") == "https://fangxiangji.gymjilv.cn/"
                   and item.get("tool") is not None))

    out = run(norm, Args, "")
    checks.append(("用例 4（⑤b 无输出 → 空数组 + 说明）",
                   out["findings"] == [] and "无输出" in out["note"]))

    # 子域名发现登记的范围外资产：只登记、不探测，必须透传出来给报告用
    out = run(norm, Args, json.dumps({
        "findings": [],
        "pending_assets": ["mail.gymjilv.cn", "vpn.gymjilv.cn"]}, ensure_ascii=False))
    checks.append(("用例 5（待授权确认资产透传）",
                   out["findings"] == [] and out["pending_assets"] == ["mail.gymjilv.cn", "vpn.gymjilv.cn"]))

    # 工具节点常见的 MCP 包装：{"content":[{"type":"text","text":"<json 字符串>"}]}
    mcp_wrapped = json.dumps({"content": [{"type": "text", "text": json.dumps(
        {"findings": [{"id": "CONF-008", "title": "缺少 CSP 响应头", "severity": "低",
                       "url": "http://127.0.0.1:8899/", "confidence": "confirmed",
                       "category": "配置缺陷"}]}, ensure_ascii=False)}]}, ensure_ascii=False)
    out = run(norm, Args, "", scope=SCOPE_RANGE, payload_name="mcp_payload", payload_value=mcp_wrapped)
    checks.append(("用例 6（MCP 包装里的内层 JSON 被挖出）",
                   len(out["findings"]) == 1
                   and out["findings"][0]["severity"] == "low"
                   and out["findings"][0]["confidence"] == 0.9))

    # 完全认不出来时，note 里要带上上游结构，便于从日志定位
    out = run(norm, Args, "", payload_name="mcp_payload",
              payload_value=json.dumps({"unknown_key": [{"a": 1}], "meta": {"x": 1}},
                                       ensure_ascii=False))
    checks.append(("用例 7（认不出清单时打印上游结构）",
                   out["findings"] == [] and "上游结构" in out["note"]
                   and "unknown_key" in out["note"]))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))


if __name__ == "__main__":
    main()
