"""报告导出验证：四种格式、两种落地方式、Excel 兼容性。

用例 1：平台没有文件桶 → 走"文本内交付"，仍给出可下载链接（data URI）；
用例 2：平台注入了文件桶（模拟）→ 四种格式都能落盘，并在交付区标注路径；
用例 3：CSV 带 UTF-8 BOM、CRLF 换行、被抑制条目单列一栏；
用例 4：HTML 自包含（没有外部样式/脚本引用），因此可以离线打开、打印成 PDF。
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


class FakeBucket:
    """模拟平台注入的文件桶。"""

    def __init__(self):
        self.saved = {}

    def save(self, filename, content):
        FakeBucket.last = self
        self.saved[filename] = content
        return "filebucket://%s" % filename


def build_args(Args):
    findings = [
        {"id": "F-001", "asset": "fangxiangji.gymjilv.cn", "url": "https://fangxiangji.gymjilv.cn/",
         "type": "misconfig", "rule_id": "MISCONFIG.MISSING_HEADER.content-security-policy",
         "title": "CSP 缺失：content-security-policy", "severity": "medium", "level": "P1",
         "risk_score": 0.3861, "confidence": 0.95, "status": "confirmed", "verified": True,
         "source_line": "both", "tools": ["headers-baseline", "恒巡能力集"],
         "affected_urls": ["https://fangxiangji.gymjilv.cn/"], "occurrences": 1,
         "evidence": ["响应头中未出现 content-security-policy"], "cwe": "CWE-16", "location": "content-security-policy"},
        {"id": "F-002", "asset": "fangxiangji.gymjilv.cn", "url": "https://fangxiangji.gymjilv.cn/",
         "type": "leak", "rule_id": "LEAK.KEYWORD.内部资料", "title": "命中自定义敏感关键词：内部资料",
         "severity": "high", "level": "P0", "risk_score": 0.9, "confidence": 0.8,
         "status": "suppressed", "verified": False, "source_line": "passive",
         "suppress_reason": "该页面为联调环境，样例数据属已知例外",
         "affected_urls": ["https://fangxiangji.gymjilv.cn/"], "occurrences": 1,
         "evidence": ["命中关键词（已脱敏）：内**料"], "cwe": "CWE-200", "location": "页面内容"},
    ]
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": findings, "stats": {"by_level": {"P1": 1}, "raw": 2,
                                                                    "merged": 2, "suppressed": 1}},
                                    ensure_ascii=False),
        explain_payload=json.dumps([{"id": "F-001", "impact": "缺失 CSP 会削弱纵深防御。",
                                     "remediation": "运维：在 Nginx 添加 CSP 响应头；验证：curl -I 查看。",
                                     "cwe_name": "CWE-16 配置"}], ensure_ascii=False),
        discover_payload=json.dumps({"pages": [{"url": "https://fangxiangji.gymjilv.cn/"}],
                                     "blocked": [], "assets": [{"host": "fangxiangji.gymjilv.cn"}]},
                                    ensure_ascii=False),
        alert_channel="")
    return args


def main():
    report, Args = load("report_code_node")
    checks = []

    # 用例 1：无文件桶 → 文本内交付
    text = report.handler(build_args(Args))["result_key"]
    checks.append(("用例 1（无文件桶时文本内交付，小文件内嵌链接）",
                   "—— 报告交付 ——" in text and "data:text/csv" in text
                   and "data:text/html" not in text
                   and "已生成（文本内交付）" in text))
    for name in ("report_",):
        pass
    checks.append(("用例 1b（四种格式与文件名齐全）",
                   all(ext in text for ext in (".html", ".csv", ".md", ".json"))))

    # 用例 2：平台注入文件桶
    report.FileBucket = FakeBucket
    text2 = report.handler(build_args(Args))["result_key"]
    saved = FakeBucket.last.saved
    checks.append(("用例 2（注入文件桶后四格式落盘）",
                   len(saved) == 4 and all(k.endswith(ext) for k, ext in
                                           zip(sorted(saved), [".csv", ".html", ".json", ".md"]))
                   and "filebucket://" in text2))

    # 用例 3：CSV 兼容 Excel
    csv_text = next(v for k, v in saved.items() if k.endswith(".csv")).decode("utf-8")
    checks.append(("用例 3（CSV 带 BOM / CRLF / 抑制列）",
                   csv_text.startswith("\ufeff") and "\r\n" in csv_text
                   and "是否抑制" in csv_text and "该页面为联调环境" in text2))

    # 用例 4：HTML 自包含
    html = next(v for k, v in saved.items() if k.endswith(".html")).decode("utf-8")
    checks.append(("用例 4（HTML 自包含可离线打开）",
                   html.startswith("<!DOCTYPE html>") and "<link" not in html
                   and "src=" not in html and "RiskScore" not in html))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    print("落盘文件：", ", ".join(sorted(saved)))
    for line in text.splitlines():
        if line.startswith("- ") or line.startswith("报告交付") or line.startswith("获取方式"):
            print("   >", line[:120])


if __name__ == "__main__":
    main()
