"""⑤b 输入裁剪验证：把"页面全量"压成"任务简报"，体积大幅下降且关键信息不丢。"""

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


def fat_pages(count=30):
    return [{
        "url": "http://demo.testfire.net/page%d.jsp" % index,
        "status": 200,
        "title": "页面 %d 标题" % index,
        "headers": {key: "x" * 120 for key in
                    ("content-type", "content-security-policy", "server", "date", "set-cookie",
                     "x-powered-by", "strict-transport-security", "x-frame-options")},
        "body_excerpt": "正" * 800,
        "resources": ["/static/a.js", "/static/b.css", "/static/c.png"] * 5,
    } for index in range(count)]


def main():
    prep, Args = load("tool_input_prep_code_node")
    payload = {"result_key": json.dumps({
        "pages": fat_pages(prep.MAX_URLS + 10),          # 故意超过上限，验证截断生效
        "assets": [{"host": "demo.testfire.net"}],
        "stats": {"pages": 30, "requests": 30, "seconds": 3.2},
        "errors": [], "blocked": [],
    }, ensure_ascii=False)}
    gate = {"result_key": json.dumps({
        "valid": 1,
        "scope_snapshot": json.dumps({"exact_domains": ["demo.testfire.net"],
                                      "exclude": {"paths": ["/__control/"]},
                                      "rate_limit_qps": 3}),
        "sensitive_rules": json.dumps({"keywords": ["内部资料", "身份证"], "file_types": ["csv"],
                                       "regex": [{"name": "手机号"}]}),
    }, ensure_ascii=False)}
    args = Args()
    args.input = types.SimpleNamespace(pages_payload=payload, gate_payload=gate)
    out = json.loads(prep.handler(args)["result_key"])

    raw_size = len(payload["result_key"])
    brief_size = len(json.dumps(out, ensure_ascii=False))
    checks = [
        ("用例 1（体积压缩到 1/5 以下）", brief_size * 5 < raw_size),
        ("用例 2（URL 与目标被截断到上限）",
         len(out["urls"]) == prep.MAX_URLS and len(out["targets"]) == 1),
        ("用例 3（授权边界摘要保留）",
         out["scope"]["domains"] == ["demo.testfire.net"]
         and out["scope"]["excluded_paths"] == ["/__control/"]
         and out["scope"]["rate_limit_qps"] == 3),
        ("用例 4（敏感规则摘要保留）",
         "内部资料" in out["sensitive"]["keywords"] and out["sensitive"]["regex_count"] == 1),
        ("用例 5（不再携带正文与响应头）",
         "body_excerpt" not in json.dumps(out) and "set-cookie" not in json.dumps(out)),
    ]
    print("=" * 70)
    print("原始输出 %d 字 → 简报 %d 字（压缩 %.0f%%）" % (raw_size, brief_size,
                                                  100 * (1 - brief_size / raw_size)))
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))


if __name__ == "__main__":
    main()
