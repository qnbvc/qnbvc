"""本地验证：起一个真实 HTTP 服务，跑一遍资产发现代码节点。

运行： python framework/platform/test_discover_node.py
"""

import functools
import http.server
import importlib.util
import json
import sys
import threading
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # framework/
SITE = ROOT / "demo_site"


def load_module():
    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    spec = importlib.util.spec_from_file_location(
        "discover_code_node", Path(__file__).with_name("discover_code_node.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, Args


def serve(directory):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def main():
    module, Args = load_module()
    module.RESPECT_ROBOTS = False        # 本地演示站没有 robots.txt
    module.DELAY_PER_HOST = 0.05         # 测试时加快限速间隔

    server, port = serve(SITE)
    host = "127.0.0.1:%d" % port
    snapshot = {
        "version": "v-test",
        "domains": ["127.0.0.1"],        # 授权范围（主机名维度）
        "exact_domains": [host],         # 精确入口（带端口，便于本地测试）
        "ip_ranges": [],
        "exclude": {"paths": ["/news"], "patterns": []},   # 故意排除 /news 用于验证拦截
        "max_depth": 2,
        "max_requests_per_run": 50,
    }
    payload = {"scope_snapshot": json.dumps(snapshot, ensure_ascii=False)}

    args = Args()
    args.input = types.SimpleNamespace(gate_payload=json.dumps(payload, ensure_ascii=False))
    result = json.loads(module.handler(args)["result_key"])

    print("=" * 72)
    print("stats   :", json.dumps(result["stats"], ensure_ascii=False))
    print("页面清单：")
    for page in result["pages"]:
        print("   [%s] depth=%s %s | 标题=%s | 外链 %d 条 / 资源 %d 个"
              % (page["status"], page["depth"], page["url"], page["title"] or "-",
                 len(page["links"]), len(page["resources"])))
    print("合规拦截：", json.dumps(result["blocked"], ensure_ascii=False))
    print("错误    ：", json.dumps(result["errors"], ensure_ascii=False))
    print("资产统计：", json.dumps(result["assets"], ensure_ascii=False))
    server.shutdown()


if __name__ == "__main__":
    main()
