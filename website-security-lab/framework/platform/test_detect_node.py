"""本地端到端验证：④ 资产发现 → ⑤ 三类检测（起真实 HTTP 服务，跑 demo_site）。"""

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
    module.RESPECT_ROBOTS = False
    module.DELAY_PER_HOST = 0.05
    return module, Args


def main():
    discover, Args = load("discover_code_node")
    detect, _ = load("detect_code_node")
    detect.DELAY_PER_HOST = 0.05

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = "127.0.0.1:%d" % server.server_address[1]

    snapshot = {
        "version": "v-test",
        "domains": ["127.0.0.1"],
        "exact_domains": [host],
        "ip_ranges": [],
        "exclude": {"paths": [], "patterns": []},
        "max_depth": 2,
        "max_requests_per_run": 50,
        "active_assets": [host],          # T1 授权（暴露面探测需要）
    }
    rules = {
        "version": "r-test",
        "keywords": ["内部资料", "仅供内部使用"],
        "regex": [{"name": "中国大陆手机号", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"},
                  {"name": "AccessKeyId", "pattern": r"(?i)(access[-_]?key[-_]?id)\s*[=:]\s*\S+"}],
        "file_types": ["csv"],
        "whitelist": ["13800000000"],
    }
    gate_payload = json.dumps({"valid": 1, "errors": "[]",
                               "scope_snapshot": json.dumps(snapshot, ensure_ascii=False),
                               "sensitive_rules": json.dumps(rules, ensure_ascii=False)},
                              ensure_ascii=False)

    args = Args()
    args.input = types.SimpleNamespace(gate_payload=gate_payload)
    pages_payload = discover.handler(args)["result_key"]
    print("④ 发现结果 stats:", json.loads(pages_payload)["stats"])

    args2 = Args()
    args2.input = types.SimpleNamespace(pages_payload=pages_payload, rules_payload=gate_payload,
                                        baseline_payload="")
    result = json.loads(detect.handler(args2)["result_key"])

    print("=" * 72)
    print("⑤ 检测 stats  :", json.dumps(result["stats"], ensure_ascii=False))
    print("⑤ 跳过项     :", json.dumps(result["skipped"], ensure_ascii=False))
    print("命中明细：")
    for item in result["findings"]:
        print("   [%-8s|%-8s] %-46s %s" % (item["severity"], item["type"],
                                           item["title"], item["url"]))
        print("       规则=%s 位置=%s 证据=%s" % (item["rule_id"], item["location"], item["evidence"]))
    server.shutdown()


if __name__ == "__main__":
    main()
