"""本地端到端验证：④ → ⑤ → ⑥ → ⑦(模拟) → ⑧ 报告生成与告警。"""

import functools
import http.server
import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "demo_site"


def load(name):
    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if hasattr(module, "RESPECT_ROBOTS"):
        module.RESPECT_ROBOTS = False
    if hasattr(module, "DELAY_PER_HOST"):
        module.DELAY_PER_HOST = 0.05
    return module, Args


def main():
    discover, Args = load("discover_code_node")
    detect, _ = load("detect_code_node")
    dedup, _ = load("dedup_code_node")
    report, _ = load("report_code_node")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = "127.0.0.1:%d" % server.server_address[1]

    snapshot = {"version": "v-test", "domains": ["127.0.0.1"], "exact_domains": [host],
                "ip_ranges": [], "exclude": {"paths": ["/config"], "patterns": []},
                "max_depth": 2, "max_requests_per_run": 50, "active_assets": [host]}
    rules = {"keywords": ["内部资料"], 
             "regex": [{"name": "中国大陆手机号", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"}],
             "file_types": ["csv"], "whitelist": ["13800000000"]}
    gate_payload = json.dumps({"valid": 1, "errors": "[]",
                               "scope_snapshot": json.dumps(snapshot, ensure_ascii=False),
                               "sensitive_rules": json.dumps(rules, ensure_ascii=False)},
                              ensure_ascii=False)

    a = Args(); a.input = types.SimpleNamespace(gate_payload=gate_payload)
    discover_payload = discover.handler(a)["result_key"]

    b = Args(); b.input = types.SimpleNamespace(pages_payload=discover_payload,
                                                rules_payload=gate_payload, baseline_payload="")
    findings_payload = detect.handler(b)["result_key"]

    c = Args(); c.input = types.SimpleNamespace(findings_payload=findings_payload)
    dedup_payload = dedup.handler(c)["result_key"]

    # ⑦ 模型节点输出：这里模拟"只解释了前两条 + 外面裹了 markdown 代码块"的最坏情况
    merged = json.loads(dedup_payload)["findings"]
    explain = [{"id": merged[0]["id"],
                "impact": "备份文件可被匿名下载，攻击者无需认证即可获取站点源码或数据库配置，可能导致凭据泄露与全站失陷。",
                "remediation": "运维：在 Nginx/网关屏蔽该路径并清理网站根目录下的备份文件；安全：复采验证返回 404/403。",
                "cwe_name": "CWE-538 文件与目录信息暴露"},
               {"id": merged[1]["id"],
                "impact": "日志文件对外可读，可能泄露内部路径、账号与业务数据。",
                "remediation": "运维：限制日志目录访问并移出站点目录。",
                "cwe_name": "CWE-532 日志信息泄露"}]
    explain_payload = "```json\n" + json.dumps(explain, ensure_ascii=False) + "\n```"   # 故意加代码块

    d = Args()
    d.input = types.SimpleNamespace(findings_payload=dedup_payload, explain_payload=explain_payload,
                                    discover_payload=discover_payload)
    result = json.loads(report.handler(d)["result_key"])

    print("=" * 78)
    print("⑧ summary:", result["summary"])
    print("⑧ alert  :", json.dumps(json.loads(result["alert"]["payload"]) if result["alert"]["payload"] else {},
                                   ensure_ascii=False)[:220])
    print("-" * 78)
    print(result["report"]["markdown"][:1800])
    print("-" * 78)
    print("Markdown 长度 %d 字符 / HTML 长度 %d 字符"
          % (len(result["report"]["markdown"]), len(result["report"]["html"])))
    server.shutdown()


if __name__ == "__main__":
    main()
