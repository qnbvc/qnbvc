"""复现线上现象：模型把域名抄错一个字母（gymjilv → bymjilv），报告必须自动回正。

用例 1：模型给出的"修复建议"里域名被抄错 → 报告里必须出现实测域名，且不含错域名；
用例 2：模型写了一个真实存在但无关的外部域名（如 example.com）→ 原样保留，不误纠。
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

ASSET = "fangxiangji.gymjilv.cn"


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
        module.LLM_ENABLED = False               # 离线跑，不走内置模型调用
    return module, Args


def build(findings, Args, remediation):
    explain = [{"id": item["id"], "impact": "缺少该防护头会削弱纵深防御。",
                "remediation": remediation, "cwe_name": "CWE-16 配置"} for item in findings]
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": findings, "stats": {"by_level": {"P2": len(findings)}}},
                                    ensure_ascii=False),
        explain_payload=json.dumps({"result_key": json.dumps(explain, ensure_ascii=False)},
                                   ensure_ascii=False),
        discover_payload=json.dumps({"pages": [{"url": "https://%s/" % ASSET}], "blocked": []},
                                    ensure_ascii=False),
        alert_channel="")
    return args


def main():
    report, Args = load("report_code_node")
    findings = [{
        "id": "F-004", "asset": ASSET, "url": "https://%s/" % ASSET, "type": "misconfig",
        "rule_id": "MISCONFIG.MISSING_HEADER.x-content-type-options", "title": "MIME 嗅探防护头缺失",
        "severity": "low", "level": "P2", "risk_score": 0.1544, "confidence": 0.95,
        "status": "confirmed", "verified": True, "source_line": "passive",
        "affected_urls": ["https://%s/" % ASSET], "occurrences": 1, "tool": "headers-baseline",
        "tools": ["headers-baseline"], "location": "x-content-type-options",
        "evidence": ["响应头中未出现 x-content-type-options"], "cwe": "CWE-16",
    }]

    typo = report.handler(build(findings, Args,
                                "运维：在 Nginx 添加 add_header X-Content-Type-Options \"nosniff\" always;"
                                "验证：curl -sI https://fangxiangji.bymjilv.cn/ | grep -i x-content-type-options"))
    text = typo["result_key"]
    ok1 = ASSET in text and "bymjilv" not in text
    print("用例 1（错域名回正）：", "通过" if ok1 else "失败")
    print("   命中实测域名：%s / 残留错域名：%s" % (ASSET in text, "bymjilv" in text))
    for line in text.splitlines():
        if "curl" in line or "纠偏" in line:
            print("   >", line.strip())

    unrelated = report.handler(build(findings, Args,
                                     "运维：参考 https://example.com/docs 的配置说明后补齐响应头。"))
    text2 = unrelated["result_key"]
    ok2 = "example.com" in text2
    print("用例 2（无关域名不误纠）：", "通过" if ok2 else "失败")


if __name__ == "__main__":
    main()
