r"""③ 策略校验与上下文构建 —— 本地离线测试脚本。

用途：不用上传到平台，就能验证代码逻辑（尤其是三条拒绝路径和三级合并）。
运行：在 website-security-lab 项目根目录下执行
      python framework\platform\test_policy_node.py
"""

import importlib.util
import io
import json
import sys
import types
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def load_node():
    """模拟平台的 runtime.Args，加载节点代码。"""

    runtime = types.ModuleType("runtime")

    class Args:
        pass

    runtime.Args = Args
    sys.modules["runtime"] = runtime
    path = Path(__file__).with_name("policy_code_node.py")
    spec = importlib.util.spec_from_file_location("policy_code_node", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, Args


def answer(value):
    """模拟交互节点·填空/单选的答案结构：{_question,_answer,_options}。"""

    return {"_question": "q", "_answer": value, "_options": {}}


def multi(values):
    """模拟交互节点·多选的答案结构：_answer 是 {A:…, B:…} 字典。"""

    return {"_question": "q",
            "_answer": {chr(65 + index): value for index, value in enumerate(values)},
            "_options": {}}


def base_inputs(**overrides):
    """一份"标准巡检配置"，用例里按需覆盖。"""

    data = dict(
        auth_confirmed=answer({"A": "✅ 已获书面授权"}),
        auth_targets=answer("portal.example.gov.cn"),
        scope_exclude=answer("/admin/export"),
        schedule=answer("每天 02:00 巡检，仅 02:00-05:00 发请求"),
        sensitive_keywords=answer("内部资料,仅供内部使用"),
        sensitive_regex=answer(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
        sensitive_filetypes=multi([".env", ".sql"]),
        sensitive_sample=answer(""),
        alert_channel=answer("webhook:https://webhook.site/demo"),
        default_keywords=answer("身份证,手机号,银行卡"),
        default_filetypes=answer(".env,.sql,.bak"),
        default_regex=answer(r"\d{17}[\dXx]"),
        rate_limit_qps=answer("5"),
        user_agent=answer("SiteSecurityInspector/1.0 (+authorized-scan)"),
    )
    data.update(overrides)
    return data


def run_case(module, Args, title, expect_status, expect_code=None, **inputs):
    args = Args()
    args.input = types.SimpleNamespace(**base_inputs(**inputs))
    result = json.loads(module.handler(args)["result_key"])
    ok = result["status"] == expect_status and (expect_code is None or result["error_code"] == expect_code)
    print("%s %s" % ("[通过]" if ok else "[失败]", title))
    print("        status=%s error_code=%s" % (result["status"], result["error_code"]))
    if result["status"] == "OK":
        snapshot = result["scope_snapshot"]
        rules = result["sensitive_rules"]
        print("        域名=%s" % snapshot["domains"])
        print("        排除=%s 时间窗=%s QPS=%s" % (snapshot["exclude"]["paths"],
                                                  snapshot["window"], snapshot["rate_limit_qps"]))
        print("        规则来源=%s | 关键词=%s | 文件类型=%s"
              % (rules["sources"]["keywords"], rules["keywords"][:3], rules["file_types"]))
        for item in result["warnings"][:2]:
            print("        [告警] %s" % item)
    else:
        print("        拒绝原因：%s" % result["error_message"])
    return ok


def main():
    module, Args = load_node()
    print("=" * 78)
    passed = []

    passed.append(run_case(module, Args, "用例1 问答全填 → 正常通过", "OK", 0))
    passed.append(run_case(module, Args, "用例2 问答留空 → 下沉到预设默认值", "OK", 0,
                           sensitive_keywords=answer(""), sensitive_regex=answer(""),
                           sensitive_filetypes=multi([])))
    passed.append(run_case(module, Args, "用例3 授权未确认 → 拒绝执行", "DENIED", 1,
                           auth_confirmed=answer({"A": "❌ 暂无授权"})))
    passed.append(run_case(module, Args, "用例4 裸通配 → 拒绝执行", "DENIED", 4,
                           auth_targets=answer("*")))
    passed.append(run_case(module, Args, "用例5 坏正则 → 跳过并告警（仍通过）", "OK", 0,
                           sensitive_regex=answer("([0-9")))
    passed.append(run_case(module, Args, "用例6 QPS 越界 → 夹逼到 20", "OK", 0,
                           rate_limit_qps=answer("999")))

    print("=" * 78)
    print("结果：%d/%d 通过" % (sum(passed), len(passed)))
    return 0 if all(passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
