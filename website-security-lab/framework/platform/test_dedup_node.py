"""本地端到端验证：④ 资产发现 → ⑤ 三类检测 → ⑥ 去重验证分级。"""

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

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = "127.0.0.1:%d" % server.server_address[1]

    snapshot = {"version": "v-test", "domains": ["127.0.0.1"], "exact_domains": [host],
                "ip_ranges": [], "exclude": {"paths": [], "patterns": []},
                "max_depth": 2, "max_requests_per_run": 50, "active_assets": [host]}
    rules = {"keywords": ["内部资料", "仅供内部使用"],
             "regex": [{"name": "中国大陆手机号", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"},
                       {"name": "AccessKeyId", "pattern": r"(?i)(access[-_]?key[-_]?id)\s*[=:]\s*\S+"}],
             "file_types": ["csv"], "whitelist": ["13800000000"]}
    gate_payload = json.dumps({"valid": 1, "errors": "[]",
                               "scope_snapshot": json.dumps(snapshot, ensure_ascii=False),
                               "sensitive_rules": json.dumps(rules, ensure_ascii=False)},
                              ensure_ascii=False)

    a1 = Args()
    a1.input = types.SimpleNamespace(gate_payload=gate_payload)
    pages_payload = discover.handler(a1)["result_key"]

    a2 = Args()
    a2.input = types.SimpleNamespace(pages_payload=pages_payload, rules_payload=gate_payload,
                                     baseline_payload="")
    findings_payload = detect.handler(a2)["result_key"]

    a3 = Args()
    a3.input = types.SimpleNamespace(findings_payload=findings_payload)
    result = json.loads(dedup.handler(a3)["result_key"])

    print("=" * 78)
    print("⑥ stats:", json.dumps(result["stats"], ensure_ascii=False))
    print("-" * 78)
    for item in result["findings"]:
        print("[%s|%-9s] %-40s 风险分=%-6s 置信度=%s 状态=%s 影响页=%d"
              % (item["level"], item["type"], item["title"][:38], item["risk_score"],
                 item["confidence"], item["status"], item["occurrences"]))
        for url in item["affected_urls"][:3]:
            print("        - %s" % url)
    server.shutdown()


if __name__ == "__main__":
    main()
