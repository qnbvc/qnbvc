"""模拟平台真实行为跑全链路：上游输出被包成 {"result_key": "<内层 JSON>"} 再传给下游。

同时模拟交互节点的答案结构：单选返回 {"_answer": {"A": "文本"}, ...}。
运行： python framework/platform/test_wrapped_chain.py
"""

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


def as_platform(module_output, Args, **field_map):
    """把某个节点的返回值，按平台"被引用时"的形态再喂给下游。

    平台行为：引用上游参数时传下来的是 {"result_key": "<该节点 result_key 的字符串值>"}。
    """

    args = Args()
    wrapped = {"result_key": module_output["result_key"]}
    args.input = types.SimpleNamespace(**{k: json.dumps(wrapped, ensure_ascii=False)
                                          for k in field_map})
    return args


def answer(question, value, options=None):
    """模拟交互节点的答案结构。"""

    if options:
        return {"_question": question, "_answer": {"A": value}, "_options": options}
    return {"_question": question, "_answer": value, "_options": {}}


def main():
    gate, Args = load("gate_code_node")
    discover, _ = load("discover_code_node")
    detect, _ = load("detect_code_node")
    dedup, _ = load("dedup_code_node")
    report, _ = load("report_code_node")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = "127.0.0.1:%d" % server.server_address[1]

    # ---- ③ 合规闸门：输入是交互节点的答案对象（模拟平台结构）----
    a1 = Args()
    a1.input = types.SimpleNamespace(
        auth_targets=answer("授权域名或 IP 段", "portal.example.gov.cn, %s" % host),
        scope_exclude=answer("排除路径", "无"),
        schedule=answer("巡检周期", "每天 02:00 巡检，仅 02:00-05:00 发请求"),
        sensitive_keywords=answer("敏感关键词", "内部资料, 仅供内部使用"),
        sensitive_regex=answer("敏感正则", r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    )
    gate_out = gate.handler(a1)
    gate_inner = json.loads(gate_out["result_key"])
    print("③ 校验结论:", gate_inner["summary"][:60], "| valid =", gate_inner["valid"])

    # ③ 的输出里把域名换成测试站点，重新走一遍（模拟真实授权域名）
    snapshot = json.loads(gate_inner["scope_snapshot"])
    snapshot.update({"domains": ["127.0.0.1"], "exact_domains": [host],
                     "active_assets": [host], "exclude": {"paths": [], "patterns": []}})
    gate_out = {"result_key": json.dumps({**gate_inner,
                                          "scope_snapshot": json.dumps(snapshot, ensure_ascii=False)},
                                         ensure_ascii=False)}

    # ---- ④ 资产发现：输入按平台形态传入 ----
    a2 = as_platform(gate_out, Args, gate_payload="gate_payload")
    discover_out = discover.handler(a2)
    discover_inner = json.loads(discover_out["result_key"])
    print("④ 发现:", json.dumps(discover_inner["stats"], ensure_ascii=False),
          "| errors:", discover_inner["errors"][:1])

    # ---- ⑤ 三类检测 ----
    a3 = as_platform(gate_out, Args, rules_payload="rules_payload")
    a3.input.pages_payload = json.dumps({"result_key": discover_out["result_key"]}, ensure_ascii=False)
    detect_out = detect.handler(a3)
    detect_inner = json.loads(detect_out["result_key"])
    print("⑤ 检测:", json.dumps(detect_inner["stats"], ensure_ascii=False))

    # ---- ⑥ 去重验证分级 ----
    a4 = as_platform(detect_out, Args, findings_payload="findings_payload")
    dedup_out = dedup.handler(a4)
    dedup_inner = json.loads(dedup_out["result_key"])
    print("⑥ 去重:", json.dumps(dedup_inner["stats"], ensure_ascii=False))

    # ---- ⑦ 模型节点输出（模拟）——同样被平台包一层 ----
    findings = dedup_inner["findings"]
    explain = [{"id": findings[0]["id"], "impact": "备份文件可被匿名下载，可能导致凭据与源码泄露。",
                "remediation": "运维：屏蔽该路径并清理文件；安全：复采验证返回 404。",
                "cwe_name": "CWE-538 文件与目录信息暴露"}] if findings else []
    explain_out = {"result_key": json.dumps(explain, ensure_ascii=False)}

    # ---- ⑧ 报告与告警 ----
    a5 = as_platform(dedup_out, Args, findings_payload="findings_payload")
    a5.input.explain_payload = json.dumps({"result_key": explain_out["result_key"]}, ensure_ascii=False)
    a5.input.discover_payload = json.dumps({"result_key": discover_out["result_key"]}, ensure_ascii=False)
    report_out = report.handler(a5)
    report_text = report_out["result_key"]
    try:                                  # 老版本返回 JSON，新版本直接返回可读报告文本
        report_text = json.loads(report_text)["summary"]
    except Exception:
        pass
    print("=" * 78)
    print("⑧ 报告前 8 行：")
    for line in str(report_text).splitlines()[:8]:
        print("   ", line)
    server.shutdown()


if __name__ == "__main__":
    main()
