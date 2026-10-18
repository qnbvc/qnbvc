"""多授权目标时，报告必须把每个目标的采集结果摊开——不能只显示成功那个。

场景取自线上实录：授权目标填了 `fangxiangji.gymjilv.cn, 118.178.130.95:8080`，
报告只出现前者，后者静默失败，看不出任何异常。
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


def build(Args):
    discover = {
        "pages": [{"url": "https://fangxiangji.gymjilv.cn/", "status": 200}],
        "blocked": [],
        "errors": [{"url": "http://118.178.130.95:8080/",
                    "error": "<urlopen error [Errno 111] Connection refused>"}],
        "stats": {"pages": 1, "requests": 3, "seconds": 1.2,
                  "seed_urls": ["https://fangxiangji.gymjilv.cn/", "https://118.178.130.95:8080/"]},
    }
    findings = [{"id": "F-001", "asset": "fangxiangji.gymjilv.cn", "url": "https://fangxiangji.gymjilv.cn/",
                 "type": "misconfig", "rule_id": "MISCONFIG.MISSING_HEADER.referrer-policy",
                 "title": "Referrer-Policy 缺失", "severity": "info", "level": "P3",
                 "risk_score": 0.0429, "confidence": 0.95, "status": "confirmed",
                 "source_line": "passive", "tools": ["headers-baseline"],
                 "affected_urls": ["https://fangxiangji.gymjilv.cn/"], "occurrences": 1,
                 "evidence": ["响应头中未出现 referrer-policy"], "cwe": "CWE-16",
                 "location": "referrer-policy"}]
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": findings, "stats": {"by_level": {"P3": 1},
                                                                    "raw": 1, "merged": 1}},
                                    ensure_ascii=False),
        explain_payload="[]",
        discover_payload=json.dumps(discover, ensure_ascii=False),
        alert_channel="")
    return args


def main():
    report, Args = load("report_code_node")
    text = report.handler(build(Args))["result_key"]
    checks = [
        ("用例 1（列出每个授权目标的采集结果）",
         "授权目标采集情况" in text and "fangxiangji.gymjilv.cn" in text
         and "118.178.130.95:8080" in text),
        ("用例 2（失败目标标注原因）",
         "采集失败" in text and "Connection refused" in text),
        ("用例 3（运行数据汇总失败目标数）",
         "授权目标 2 个（失败 1 个）" in text),
    ]
    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    for line in text.splitlines():
        if line.startswith("| https") or line.startswith("覆盖"):
            print("   >", line.strip())


if __name__ == "__main__":
    main()
