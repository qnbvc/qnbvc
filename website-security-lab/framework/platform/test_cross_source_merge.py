"""跨来源合并：能力集/工具线用中文命名报出的问题，必须与自研被动线的同一条合并。

场景取自 `run_inspection`（恒巡能力集）这类现成能力包：
它报"缺少内容安全策略响应头 CSP"，自研线报"MISCONFIG.MISSING_HEADER.content-security-policy"，
如果合不到一起，同一处问题就会在报告里出现两条，准确率与去重效果都受影响。
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
    return module, Args


PASSIVE = [
    {"asset": "a.example", "url": "https://a.example/", "type": "misconfig",
     "rule_id": "MISCONFIG.MISSING_HEADER.content-security-policy", "title": "CSP 缺失：content-security-policy",
     "severity": "medium", "tool": "headers-baseline", "tier": "T0",
     "location": "content-security-policy", "evidence": "响应头中未出现 content-security-policy",
     "confidence": 0.8},
    {"asset": "a.example", "url": "https://a.example/", "type": "malware",
     "rule_id": "MALWARE.HIDDEN_LINK", "title": "隐藏链接（暗链）", "severity": "high",
     "tool": "malware-signature", "tier": "T0", "location": "HTML 源码",
     "evidence": "命中片段：<a style=\"display:none\" href=...>", "confidence": 0.65},
]

TOOL_LINE = [
    {"asset": "a.example", "url": "https://a.example/", "type": "misconfig",
     "rule_id": "WEAK_CONFIG.csp_missing", "title": "缺少内容安全策略响应头（CSP）",
     "severity": "medium", "tool": "恒巡能力集", "tier": "T1", "location": "HTTP 响应头",
     "evidence": "响应头中未发现 CSP", "confidence": 0.85},
    {"asset": "a.example", "url": "https://a.example/", "type": "malware",
     "rule_id": "MALICIOUS.hidden_link", "title": "页面存在暗链", "severity": "high",
     "tool": "恒巡能力集", "tier": "T1", "location": "页面底部",
     "evidence": "发现 display:none 的外链", "confidence": 0.8},
    {"asset": "a.example", "url": "https://a.example/", "type": "tamper",
     "rule_id": "TAMPER.page_changed", "title": "页面内容与基线不一致（疑似篡改）",
     "severity": "high", "tool": "恒巡能力集", "tier": "T1", "location": "首页",
     "evidence": "首页正文哈希与上一轮基线不一致", "confidence": 0.9},
    {"asset": "a.example", "url": "https://a.example/", "type": "misconfig",
     "rule_id": "WEAK_CONFIG.tls", "title": "TLS 证书链不完整", "severity": "medium",
     "tool": "恒巡能力集", "tier": "T1", "location": "HTTPS 配置",
     "evidence": "证书链缺少中间证书", "confidence": 0.8},
]


def main():
    dedup, Args = load("dedup_code_node")
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": PASSIVE, "stats": {}}, ensure_ascii=False),
        tool_findings_payload=json.dumps({"result_key": json.dumps(TOOL_LINE, ensure_ascii=False)},
                                         ensure_ascii=False))
    result = json.loads(dedup.handler(args)["result_key"])

    print("stats:", json.dumps(result["stats"], ensure_ascii=False))
    for item in result["findings"]:
        print("[%s] 来源=%-9s 置信度=%s  规则=%s  位置=%s"
              % (item["id"], item.get("source_line"), item["confidence"],
                 item["rule_id"][:44], item.get("location")))

    csp = [item for item in result["findings"] if item["type"] == "misconfig"
           and "content-security-policy" in str(item.get("rule_id")) + str(item.get("location"))]
    dark = [item for item in result["findings"] if item["type"] == "malware"]
    tamper = [item for item in result["findings"] if item["type"] == "tamper"]

    checks = [
        ("CSP 两线合并为一条", len(csp) == 1 and csp[0].get("source_line") == "both"),
        ("暗链两线合并为一条", len(dark) == 1 and dark[0].get("source_line") == "both"),
        ("篡改检测（自研线没有，工具线保留）", len(tamper) == 1
         and tamper[0].get("source_line") == "tool"),
        ("去重后共 4 条（6 条原始命中）", result["stats"]["merged"] == 4
         and result["stats"]["raw"] == 6),
        ("交叉印证计数为 2", result["stats"].get("cross_verified") == 2),
    ]
    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))


if __name__ == "__main__":
    main()
