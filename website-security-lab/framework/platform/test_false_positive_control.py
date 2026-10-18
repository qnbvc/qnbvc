"""误报处置三件套的本地验证（不需要外网）：

用例 1：复采抖动 —— 第一次复采没命中、第二次命中，应判"确证"而不是"疑似已修复"；
用例 2：白名单抑制 —— 命中抑制规则的条目转为 suppressed，不计入风险统计，且跳过复采请求；
用例 3：报告留痕 —— 被抑制的条目不进正文，但出现在附录里并写明抑制原因。
"""

import http.server
import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

WITH_MARKER = "<html><body>内部资料 编号 A-1024</body></html>"
WITHOUT_MARKER = "<html><body>服务暂时不可用</body></html>"


class FlakyHandler(http.server.BaseHTTPRequestHandler):
    """第一次请求故意不含关键词（模拟响应抖动），之后正常返回。"""

    seen = 0

    def do_GET(self):                                   # noqa: N802
        FlakyHandler.seen += 1
        body = WITHOUT_MARKER if FlakyHandler.seen == 1 else WITH_MARKER
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
    if hasattr(module, "LLM_ENABLED"):
        module.LLM_ENABLED = False
    return module, Args


def passive_finding(base):
    return {"asset": base, "url": "http://%s/" % base, "type": "leak",
            "rule_id": "LEAK.KEYWORD.内部资料", "title": "命中自定义敏感关键词：内部资料",
            "severity": "high", "tool": "sensitive-scan", "tier": "T0", "location": "页面内容",
            "evidence": "命中关键词（已脱敏）：内**料", "verify_hint": "内部资料", "confidence": 0.8}


def run_dedup(dedup, Args, base, suppress=None):
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps({"findings": [passive_finding(base)], "stats": {}}, ensure_ascii=False),
        tool_findings_payload="",
        suppress_payload=json.dumps(suppress or {}, ensure_ascii=False))
    return json.loads(dedup.handler(args)["result_key"]), args.input


def main():
    dedup, Args = load("dedup_code_node")
    report, _ = load("report_code_node")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FlakyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "127.0.0.1:%d" % server.server_address[1]
    checks = []

    # 用例 1：抖动不应被当成"已修复"
    FlakyHandler.seen = 0
    result, _ = run_dedup(dedup, Args, base)
    item = result["findings"][0]
    checks.append(("用例 1（复采抖动仍判确证）",
                   item["status"] == "confirmed" and item["verified"] is True
                   and any("抖动" in str(line) for line in item["evidence"])))

    # 用例 2：白名单抑制
    FlakyHandler.seen = 0
    suppress = {"rules": [{"rule_id": "LEAK.KEYWORD", "version": "v1",
                           "reason": "该页面为联调环境，样例数据属已知例外"}]}
    result, _ = run_dedup(dedup, Args, base, suppress)
    item = result["findings"][0]
    checks.append(("用例 2（命中抑制规则转 suppressed）",
                   item["status"] == "suppressed"
                   and result["stats"]["suppressed"] == 1
                   and result["stats"]["by_level"] == {}
                   and result["stats"]["requests"] == 0))

    # 用例 3：报告附录留痕，正文不出现
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps(result, ensure_ascii=False),
        explain_payload="[]",
        discover_payload=json.dumps({"pages": [{"url": "http://%s/" % base}], "blocked": []},
                                    ensure_ascii=False),
        alert_channel="")
    text = report.handler(args)["result_key"]
    main_body, _, appendix = text.partition("## 五、误报抑制与白名单留痕")
    checks.append(("用例 3（抑制条目只在附录出现）",
                   "命中自定义敏感关键词" not in main_body and "命中自定义敏感关键词" in appendix
                   and "已知例外" in appendix and "误报处置：" in text))

    print("=" * 70)
    for label, ok in checks:
        print("%s：%s" % (label, "通过" if ok else "失败"))
    for line in text.splitlines():
        if line.startswith("误报处置") or "抑制原因" in line:
            print("   >", line.strip())
    server.shutdown()


if __name__ == "__main__":
    main()
