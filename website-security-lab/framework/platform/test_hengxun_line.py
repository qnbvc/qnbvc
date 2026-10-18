"""⑤d（云能力集 run_inspection）接进来后的端到端验证。

用例 1：中文类别/等级被翻译成内部枚举（不能把"严重"当未知等级按 info 计权）；
用例 2：能力集报的"缺失安全响应头"与自研被动线的同一条合并成一条交叉印证；
用例 3：能力集独有的篡改/挂马条目保留，且不会因 HTML 复采未命中被误判成"疑似已修复"。
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

# 模拟 run_inspection 返回的条目（字段取自靶场 ground-truth 的口径）
RANGE_FINDINGS = [
    {"id": "SENS-003", "category": "敏感信息", "type": "数据库备份可下载", "severity": "严重",
     "url": "http://127.0.0.1:8899/backup/db.sql", "title": "数据库备份文件可匿名下载",
     "evidence": "GET /backup/db.sql → 200，含用户表结构与口令哈希"},
    {"id": "CONF-008", "category": "配置缺陷", "type": "缺失安全响应头", "severity": "低",
     "url": "http://127.0.0.1:8899/", "title": "缺少 Content-Security-Policy 响应头",
     "evidence": "响应头中无 content-security-policy"},
    {"id": "TAMPER-001", "category": "挂马篡改", "type": "页面篡改", "severity": "严重",
     "url": "http://127.0.0.1:8899/notice", "title": "页面标题被改为 Hacked by BlackHatTeam",
     "evidence": "与上一轮基线比对，/notice 标题发生变化"},
    {"id": "MAL-002", "category": "挂马篡改", "type": "暗链", "severity": "高",
     "url": "http://127.0.0.1:8899/", "title": "首页存在隐藏外链（暗链）",
     "evidence": "left:-9999px 定位的外链，指向博彩类站点"},
]

PASSIVE_FINDINGS = [
    {"asset": "127.0.0.1:8899", "url": "http://127.0.0.1:8899/", "type": "misconfig",
     "rule_id": "MISCONFIG.MISSING_HEADER.content-security-policy", "title": "CSP 缺失：content-security-policy",
     "severity": "medium", "tool": "headers-baseline", "tier": "T0",
     "location": "content-security-policy", "evidence": "响应头中未出现 content-security-policy",
     "verify_hint": "", "confidence": 0.8},
]


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


def main():
    norm, Args = load("tool_norm_code_node")
    dedup, _ = load("dedup_code_node")
    checks = []

    args = Args()
    args.input = types.SimpleNamespace(
        tool_payload="",
        mcp_payload=json.dumps({"findings": RANGE_FINDINGS}, ensure_ascii=False),
        scope_payload=json.dumps({"scope_snapshot": json.dumps(
            {"active_assets": ["127.0.0.1:8899"]})}, ensure_ascii=False))
    norm_out = json.loads(norm.handler(args)["result_key"])
    normalized = {item["external_id"]: item for item in norm_out["findings"]}

    checks.append(("用例 1（中文类别/等级翻译正确）",
                   normalized["SENS-003"]["type"] == "leak"
                   and normalized["SENS-003"]["severity"] == "critical"
                   and normalized["TAMPER-001"]["type"] == "tamper"
                   and normalized["MAL-002"]["type"] == "malware"
                   and normalized["CONF-008"]["type"] == "misconfig"))

    dedup_args = Args()
    dedup_args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": PASSIVE_FINDINGS, "stats": {}}, ensure_ascii=False),
        tool_findings_payload=json.dumps({"result_key": json.dumps(norm_out, ensure_ascii=False)},
                                         ensure_ascii=False),
        suppress_payload="")
    result = json.loads(dedup.handler(dedup_args)["result_key"])
    merged = result["findings"]
    csp = [i for i in merged if "content-security-policy" in str(i.get("location", ""))]
    tamper = [i for i in merged if i.get("type") == "tamper"]
    malware = [i for i in merged if i.get("type") == "malware"]

    checks.append(("用例 2（能力集与被动线合并为交叉印证）",
                   len(csp) == 1 and csp[0].get("source_line") == "both"))
    checks.append(("用例 3（篡改/挂马作为工具线结论保留且状态合理）",
                   len(tamper) == 1 and tamper[0]["status"] == "unverified"
                   and malware and malware[0]["status"] in ("unverified", "needs_review")))
    checks.append(("用例 4（等级加权生效：严重 > 低）",
                   tamper[0]["level"] in ("P0", "P1")
                   and any(i["level"] == "P3" or i["level"] == "P2" for i in csp)))

    # 用例 5：能力集扫的站点与本轮授权目标不一致时，整条隔离（避免证据错配）
    args5 = Args()
    args5.input = types.SimpleNamespace(
        tool_payload="",
        mcp_payload=json.dumps({"findings": RANGE_FINDINGS}, ensure_ascii=False),
        scope_payload=json.dumps({"scope_snapshot": json.dumps(
            {"active_assets": ["demo.testfire.net"], "domains": ["demo.testfire.net"]})},
            ensure_ascii=False))
    out5 = json.loads(norm.handler(args5)["result_key"])
    checks.append(("用例 5（目标不一致时整条隔离，不混进报告）",
                   out5["findings"] == [] and len(out5["isolated"]) == len(RANGE_FINDINGS)
                   and "隔离" in out5["note"]))

    print("stats:", json.dumps(result["stats"], ensure_ascii=False))
    for item in merged:
        print("[%s] %-9s 来源=%-8s %s" % (item["level"], item["type"], item.get("source_line"),
                                          item["title"][:38]))
    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))


if __name__ == "__main__":
    main()
