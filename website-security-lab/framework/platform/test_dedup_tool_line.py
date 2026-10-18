"""验证 ⑥ 处理"两条线合并"时的三个关键行为（不需要外网，本地起一个被测站点）：

用例 1：工具线结论（无 verify_hint，如 sslscan 的证书链判断）→ 状态 unverified、置信度不被抬高；
用例 2：工具线结论带 verify_hint 且复采命中 → confirmed；
用例 3：被动线与工具线报同一个响应头缺失 → 合并成一条，tools 里同时出现两个来源。
"""

import http.server
import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

BODY = "<html><body>内部资料 编号 A-1024</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                   # noqa: N802
        payload = BODY.encode("utf-8")
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
        module.DELAY_PER_HOST = 0.05
    return module, Args


def run(dedup, Args, base, tool_items):
    passive = {"findings": [{
        "asset": base, "url": "http://%s/" % base, "type": "misconfig",
        "rule_id": "MISCONFIG.MISSING_HEADER.content-security-policy",
        "title": "CSP 缺失", "severity": "medium", "tool": "headers-baseline",
        "tier": "T0", "location": "content-security-policy",
        "evidence": "响应头中未出现 content-security-policy", "confidence": 0.8,
    }], "stats": {}}
    args = Args()
    args.input = types.SimpleNamespace(
        findings_payload=json.dumps(passive, ensure_ascii=False),
        tool_findings_payload=json.dumps({"result_key": json.dumps(tool_items, ensure_ascii=False)},
                                         ensure_ascii=False))
    return json.loads(dedup.handler(args)["result_key"])


def main():
    dedup, Args = load("dedup_code_node")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "127.0.0.1:%d" % server.server_address[1]

    tools = [
        {"asset": base, "url": "https://%s" % base, "type": "misconfig",
         "rule_id": "SSL_TLS.SELF_SIGNED", "title": "TLS 证书为自签名", "severity": "medium",
         "tool": "SSL TLS检测", "tier": "T1", "location": "TLS 配置",
         "evidence": ["sslscan 判定证书为自签名，客户端会提示不受信任"], "confidence": 0.98},
        {"asset": base, "url": "http://%s/" % base, "type": "misconfig",
         "rule_id": "MISCONFIG.SENSITIVE_FILE_EXPOSED", "title": "发现敏感文件可匿名访问",
         "severity": "high", "tool": "HTTP参数发现", "tier": "T1", "location": "/files/",
         "evidence": "工具返回 200，路径可直接下载", "verify_hint": "内部资料", "confidence": 0.7},
        {"asset": base, "url": "http://%s/" % base, "type": "misconfig",
         "rule_id": "nuclei.http-missing-security-headers", "title": "缺少安全响应头",
         "severity": "medium", "tool": "nuclei", "tier": "T1",
         "location": "content-security-policy", "evidence": "nuclei 模板命中缺失 CSP",
         "confidence": 0.75},
        {"asset": base, "url": "http://%s/" % base, "type": "misconfig",
         "rule_id": "SSL_TLS.CERT_CHAIN_VERIFY", "title": "TLS 证书链验证失败",
         "severity": "low", "tool": "SSL TLS检测", "tier": "T1", "location": "TLS 配置",
         "evidence": "sslscan 返回 Verify: unable to get local issuer certificate",
         "verify_hint": "unable to get local issuer certificate", "confidence": 0.7},
    ]
    result = run(dedup, Args, base, tools)
    print("stats:", json.dumps(result["stats"], ensure_ascii=False))
    print("-" * 78)
    for item in result["findings"]:
        print("[%s] 来源=%s 状态=%s 置信度=%s 风险分=%s  工具=%s"
              % (item["id"], item.get("source_line"), item["status"], item["confidence"],
                 item["risk_score"], ",".join(item.get("tools") or [])))
        print("     %s" % item["title"])
        for line in item["evidence"]:
            print("       - %s" % line)

    by_rule = {item["rule_id"]: item for item in result["findings"]}
    headers = [item for item in result["findings"]
               if "security-headers" in str(item.get("rule_id", ""))
               or "content-security-policy" in str(item.get("location", ""))]
    print("=" * 78)
    print("用例 1（工具线无 hint 不冒充确证）：",
          "通过" if by_rule["SSL_TLS.SELF_SIGNED"]["status"] == "unverified"
          and by_rule["SSL_TLS.SELF_SIGNED"]["verified"] is False else "失败")
    print("用例 2（工具线有 hint 可复采确证）：",
          "通过" if by_rule["MISCONFIG.SENSITIVE_FILE_EXPOSED"]["verified"] is True else "失败")
    print("用例 3（跨来源合并为一条）：",
          "通过" if headers and len(headers[0]["tools"]) >= 2 and headers[0]["confidence"] >= 0.95
          and headers[0].get("source_line") == "both"
          and result["stats"].get("cross_verified") == 1 else "失败")
    cert = by_rule["SSL_TLS.CERT_CHAIN_VERIFY"]
    print("用例 4（协议层结论不被 HTML 复采否定）：",
          "通过" if cert["status"] == "unverified" and cert["confidence"] == 0.7
          and cert["verified"] is False else "失败")
    server.shutdown()


if __name__ == "__main__":
    main()
