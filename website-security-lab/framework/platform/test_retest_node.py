"""⑨b 复测节点验证：只读复采、三种结论、未请求复测时不动作。

用例 1：选择"需要复测"→ 逐条复采，命中线索的判"仍存在"，线索消失的判"已修复"；
用例 2：选择"确认处置并归档"→ 不发起任何复测，只回一句说明；
用例 3：复测结论含统计与整改建议（可关闭/需跟进）。
"""

import http.server
import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

WITH_MARKER = "<html><body>CSP 相关配置片段：content-security-policy 仍未下发</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                   # noqa: N802
        body = WITH_MARKER if self.path.startswith("/still") else "<html><body>已整改</body></html>"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


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


def findings(base):
    return {"findings": [
        {"id": "F-001", "level": "P1", "type": "leak", "rule_id": "LEAK.KEYWORD.内部资料",
         "title": "命中敏感关键词", "url": "http://%s/still.html" % base,
         "verify_hint": "content-security-policy", "risk_score": 0.9},
        {"id": "F-002", "level": "P2", "type": "leak", "rule_id": "LEAK.KEYWORD.内部资料",
         "title": "命中敏感关键词（已整改）", "url": "http://%s/fixed.html" % base,
         "verify_hint": "内部资料", "risk_score": 0.5},
    ], "stats": {}}


def main():
    retest, Args = load("retest_code_node")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "127.0.0.1:%d" % server.server_address[1]
    checks = []

    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"result_key": json.dumps(findings(base), ensure_ascii=False)},
                                    ensure_ascii=False),
        report_payload="# 网站安全智能巡检报告\n\n报告已生成：风险 2 条……（正文略）",
        review_action={"review_action": {"_answer": "需要复测"}})
    text = retest.handler(args)["result_key"]
    checks.append(("用例 1（逐条复测并给出结论）",
                   "仍存在" in text and "已修复" in text and "F-001" in text and "F-002" in text))
    checks.append(("用例 3（统计与整改建议）",
                   "仍存在 1 条" in text and "已修复 1 条" in text
                   and "可关闭对应工单" in text and "需继续跟进" in text))
    checks.append(("用例 4（合并交付：报告在前、复测结论在后）",
                   text.startswith("# 网站安全智能巡检报告")
                   and text.index("报告已生成") < text.index("复测结论")))

    args2 = Args()
    args2.input = types.SimpleNamespace(
        findings_payload=json.dumps({"result_key": json.dumps(findings(base), ensure_ascii=False)},
                                    ensure_ascii=False),
        report_payload="# 网站安全智能巡检报告\n\n（正文略）",
        review_action="确认处置并归档")
    text2 = retest.handler(args2)["result_key"]
    checks.append(("用例 2（未请求复测时不动作）",
                   "未请求复测" in text2 and "复测结论" not in text2
                   and text2.startswith("# 网站安全智能巡检报告")))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    for line in text.splitlines()[:12]:
        print("   >", line)
    server.shutdown()


if __name__ == "__main__":
    main()
