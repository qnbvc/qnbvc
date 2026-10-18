"""验证 ⑥b 解释负载裁剪：字段瘦身、证据截断、条数封顶三项都要生效。"""

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


def make_finding(index, risk, evidence):
    return {"id": "F-%03d" % index, "type": "misconfig", "rule_id": "R.%d" % index,
            "title": "风险 %d" % index, "severity": "medium", "level": "P2",
            "risk_score": risk, "location": "x", "url": "https://a.example/",
            "asset": "a.example", "cwe": "CWE-16", "tool": "headers-baseline",
            "evidence": evidence, "verify_hint": "hint",
            "affected_urls": ["https://a.example/%d" % i for i in range(50)],
            "tools": ["headers-baseline"], "source_lines": ["passive"],
            "status": "confirmed", "confidence": 0.95}


def main():
    prep, Args = load("explain_prep_code_node")
    findings = [make_finding(i, 1.0 - i * 0.01, "证" * 400) for i in range(1, 21)]
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"result_key": json.dumps({"findings": findings}, ensure_ascii=False)},
                                    ensure_ascii=False))
    out = json.loads(prep.handler(args)["result_key"])

    checks = [
        ("条数封顶 %d 条" % prep.MAX_ITEMS, len(out) == prep.MAX_ITEMS),
        ("按风险分从高到低", out[0]["id"] == "F-001"),
        ("字段瘦身（不带 affected_urls / source_lines）",
         all("affected_urls" not in item and "source_lines" not in item for item in out)),
        ("证据截断到 %d 字" % prep.EVIDENCE_MAX,
         all(len(item["evidence"]) <= prep.EVIDENCE_MAX + 1 for item in out)),
        ("保留 verify_hint", all(item.get("verify_hint") == "hint" for item in out)),
    ]
    print("=" * 60)
    print("负载字符数：%d（原始约 %d）" % (len(json.dumps(out, ensure_ascii=False)),
                                        len(json.dumps(findings, ensure_ascii=False))))
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))


if __name__ == "__main__":
    main()
