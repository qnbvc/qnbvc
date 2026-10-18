# coding=utf-8
# ③ 代码节点 · 策略校验与上下文构建
#
# 输入参数（在"输入参数"面板里逐行引用）：
#   来自 ② 交互节点：auth_confirmed / auth_targets / scope_exclude / schedule /
#       sensitive_keywords / sensitive_regex / sensitive_filetypes / sensitive_sample / alert_channel
#   来自 ① 开始节点：default_keywords / default_filetypes / default_regex /
#       rate_limit_qps / user_agent
#
# 输出（result_key，JSON 字符串）：
#   status / error_code / error_message / task_id / scope_snapshot /
#   sensitive_rules / alert_channel / audit_log / warnings / summary
#
# 这个节点干五件事：
#   1) 授权闸门：未确认"已获书面授权"直接终止，不发任何请求
#   2) 范围校验：域名 / IP 段 / 排除路径的格式规范化与错误定位
#   3) 敏感定义三级合并：本次问答 > ① 预设默认值 > 内置兜底
#   4) 参数夹逼：QPS / 并发 / 超时夹到安全区间，防误配
#   5) 生成 scope_snapshot 与敏感规则集，供 ④⑤⑧ 直接消费

from runtime import Args

import ipaddress
import json
import re
import time
import uuid

# ------------------------- 可调常量 -------------------------
BUILTIN_KEYWORDS = "身份证,手机号,银行卡,内部系统,数据库连接,账号密码"
BUILTIN_FILETYPES = ".env,.sql,.bak,.zip,.log,.git"
BUILTIN_REGEX = "1[3-9]\\d{9};\\d{17}[\\dXx]"

DEFAULT_QPS = 5
DEFAULT_CONCURRENCY = 3
DEFAULT_TIMEOUT = 30
DEFAULT_UA = "SiteSecurityInspector/1.0 (+authorized-scan)"
DEFAULT_WINDOW = "00:00-23:59"
BLOCKED_METHODS = "POST,PUT,DELETE,PATCH"

QPS_RANGE = (1, 20)
CONCURRENCY_RANGE = (1, 10)
TIMEOUT_RANGE = (3, 120)
MAX_KEYWORDS = 80
MAX_REGEX = 30

DENY_WORDS = ("暂无授权", "暂不扫描", "未获", "没有授权")
CONFIRM_WORD = "已获书面授权"
ERROR_CODES = {"OK": 0, "AUTH_DENIED": 1, "OUT_OF_SCOPE": 3, "INVALID_INPUT": 4}
# -----------------------------------------------------------

DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
TIME_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
EMPTY_WORDS = {"", "无", "没有", "略", "none", "-", "/", "无。", "不限"}


# ------------------------------ 取值工具 ------------------------------

def _text(value):
    """交互节点的答案可能是 {_question,_answer,_options} / {A:…,B:…} / 纯字符串，统一取文本。"""

    if isinstance(value, dict):
        if "_answer" in value:
            return _text(value["_answer"])
        parts = [_text(item) for item in value.values()]
        return "、".join(part for part in parts if part)
    if isinstance(value, (list, tuple)):
        return "、".join(part for part in (_text(item) for item in value) if part)
    return "" if value is None else str(value)


def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def _split(text, seps=r"[,，、;；\n\r\t]+"):
    """按中英文逗号/顿号/分号/换行拆分，去空白、去重、过滤占位词。"""

    text = _text(text)
    if not text:
        return []
    items, seen = [], set()
    for part in re.split(seps, text):
        part = part.strip().strip("。;；,，、")
        if part in EMPTY_WORDS or part in seen:
            continue
        seen.add(part)
        items.append(part)
    return items


def _split_regex(text):
    """正则用分号/换行拆分——正则里常含逗号，不能用逗号拆。"""

    return _split(text, r"[;；\n\r]+")


def _clamp(raw, low, high, default):
    text = _text(raw).strip()
    if text in ("", "0", "0.0", "none", "None"):      # 未填或填 0 视为"用默认值"，不算越界
        return default, False
    try:
        value = int(float(text))
    except (TypeError, ValueError):
        return default, True
    if value < low or value > high:
        return max(low, min(high, value)), True
    return value, False


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _log(message):
    """日志兜底：某些运行环境控制台编码较窄，打印 emoji 会抛异常，不能让日志拖垮主流程。"""

    try:
        print(message)
    except Exception:
        try:
            print(str(message).encode("utf-8", "ignore").decode("ascii", "ignore"))
        except Exception:
            pass


# ------------------------------ 校验工具 ------------------------------

def _valid_domain(host):
    host = str(host or "")
    if ":" in host:                       # 容许 host:port
        host = host.split(":")[0]
    if not host or len(host) > 253 or "." not in host:
        return False
    return all(DOMAIN_LABEL_RE.match(label) for label in host.rstrip(".").split("."))


def _is_ip(text):
    text = str(text or "")
    if text.count(":") == 1:              # 去掉 host:port 里的端口
        text = text.split(":")[0]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _classify_targets(targets, errors, warnings):
    domains, wildcards, ip_ranges = [], [], []
    for item in targets:
        if "/" in item and not item.startswith("*."):
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                errors.append("IP 段格式非法：%s（%s）" % (item, exc))
                continue
            if network.prefixlen < 16:
                warnings.append("网段过大（/%d），建议收窄" % network.prefixlen)
            ip_ranges.append(item)
        elif item.strip() in ("*", "*."):
            errors.append("禁止裸通配 *，必须写清二级域（如 *.example.gov.cn）")
        elif item.startswith("*."):
            if _valid_domain(item[2:]):
                wildcards.append(item)
                warnings.append("%s 会显著扩大巡检面，请确认在授权书范围内" % item)
            else:
                errors.append("通配域名格式非法：%s" % item)
        elif "*" in item:
            errors.append("通配符只能出现在最左侧：%s" % item)
        elif _is_ip(item):
            ip_ranges.append(item)
        elif _valid_domain(item):
            domains.append(item)
        else:
            errors.append("域名格式非法：%s" % item)
    if not (domains or wildcards or ip_ranges):
        errors.append("至少需要一个授权域名或 IP 段")
    return domains, wildcards, ip_ranges


def _normalize_exclude(raw, warnings):
    paths = []
    for item in _split(raw):
        if not item.startswith("/"):
            warnings.append("%s 不是绝对路径，已自动补为 /%s" % (item, item))
            item = "/" + item.lstrip("/")
        paths.append(item)
    return paths


def _parse_window(text, warnings):
    """从自然语言里抽巡检时间窗；抽不到则默认为全时段（避免配置与实际行为矛盾）。"""

    normalized = str(text or "").replace("：", ":")
    match = re.search(r"(\d{1,2}:\d{2})\s*[-~至到]\s*(\d{1,2}:\d{2})", normalized)
    if match:
        window = "%02d:%s-%02d:%s" % (
            int(match.group(1).split(":")[0]), match.group(1).split(":")[1],
            int(match.group(2).split(":")[0]), match.group(2).split(":")[1])
        if TIME_WINDOW_RE.match(window):
            return window
        warnings.append("时间窗越界或格式错误：%s，已用默认 %s" % (window, DEFAULT_WINDOW))
        return DEFAULT_WINDOW
    only_hour = re.search(r"(\d{1,2})\s*[点时]", normalized)
    if only_hour and 0 <= int(only_hour.group(1)) <= 23:
        start = int(only_hour.group(1))
        return "%02d:00-%02d:00" % (start, min(start + 3, 23))
    return DEFAULT_WINDOW


# ------------------------------ 三级合并 ------------------------------

def _merge3(input_text, default_text, builtin_text, limit, label, warnings, splitter=_split):
    """本次问答 > ① 预设默认值 > 内置兜底；空值逐级下沉，返回 (条目, 来源)。"""

    for source, items in (("本次问答", splitter(input_text)),
                          ("预设默认值", splitter(default_text)),
                          ("内置兜底", splitter(builtin_text))):
        if items:
            if len(items) > limit:
                warnings.append("%s 共 %d 条，超出上限 %d，已截断" % (label, len(items), limit))
                items = items[:limit]
            return items, source
    return [], "空"


def _deny(code, message, summary, audit):
    _log("[策略校验] 拒绝执行：%s" % message)
    return {"result_key": json.dumps({
        "status": "DENIED", "error_code": ERROR_CODES.get(code, 9),
        "error_message": message, "task_id": "",
        "scope_snapshot": {}, "sensitive_rules": {}, "alert_channel": "",
        "audit_log": audit, "warnings": [], "summary": summary,
    }, ensure_ascii=False)}


# ------------------------------- 主逻辑 -------------------------------

def handler(args: Args) -> dict:
    started = time.time()
    errors, warnings, audit = [], [], []
    task_id = "T-%s-%s" % (time.strftime("%Y%m%d"), uuid.uuid4().hex[:6])
    try:
        # ---------- 1) 授权闸门（第一道，最硬的一道）----------
        confirmed = _text(_input(args, "auth_confirmed"))
        audit.append({"ts": _now(), "action": "auth_check",
                      "target": "auth_confirmed", "result": confirmed or "(空)"})
        if not confirmed:
            return _deny("AUTH_DENIED", "未获取授权确认（auth_confirmed 为空）",
                         "授权确认缺失，已终止执行，未发起任何请求。", audit)
        if any(word in confirmed for word in DENY_WORDS) or CONFIRM_WORD not in confirmed:
            return _deny("AUTH_DENIED", "授权确认未通过：%s" % confirmed,
                         "授权确认未通过（%s），已终止执行，未发起任何请求。" % confirmed, audit)

        # ---------- 2) 范围校验 ----------
        domains, wildcards, ip_ranges = _classify_targets(
            _split(_input(args, "auth_targets")), errors, warnings)
        exclude_paths = _normalize_exclude(_input(args, "scope_exclude"), warnings)
        window = _parse_window(_input(args, "schedule"), warnings)
        if errors:
            return _deny("INVALID_INPUT", "；".join(errors),
                         "授权范围校验未通过：%s" % "；".join(errors), audit)

        # ---------- 3) 敏感定义三级合并 ----------
        keywords, kw_src = _merge3(_input(args, "sensitive_keywords"),
                                   _input(args, "default_keywords"), BUILTIN_KEYWORDS,
                                   MAX_KEYWORDS, "敏感关键词", warnings)
        filetypes, ft_src = _merge3(_input(args, "sensitive_filetypes"),
                                    _input(args, "default_filetypes"), BUILTIN_FILETYPES,
                                    MAX_KEYWORDS, "敏感文件类型", warnings)
        regex_items, re_src = _merge3(_input(args, "sensitive_regex"),
                                      _input(args, "default_regex"), BUILTIN_REGEX,
                                      MAX_REGEX, "敏感正则", warnings, splitter=_split_regex)

        regex_rules = []
        for index, pattern in enumerate(regex_items, 1):
            try:
                re.compile(pattern)
            except re.error as exc:
                warnings.append("第 %d 条正则编译失败已跳过：%s（%s）" % (index, pattern[:40], exc))
                continue
            regex_rules.append({"name": "自定义规则%d" % index, "pattern": pattern})
        if not (keywords or regex_rules or filetypes):
            warnings.append("敏感规则全为空，泄露检测维度将不生效")

        sample_text = _text(_input(args, "sensitive_sample"))
        sample_hint = "" if sample_text in EMPTY_WORDS else sample_text.strip()[:200]

        # ---------- 4) 参数夹逼 ----------
        qps, qps_clamped = _clamp(_input(args, "rate_limit_qps"), QPS_RANGE[0], QPS_RANGE[1],
                                  DEFAULT_QPS)
        concurrency, cc_clamped = _clamp(DEFAULT_CONCURRENCY, CONCURRENCY_RANGE[0],
                                         CONCURRENCY_RANGE[1], DEFAULT_CONCURRENCY)
        timeout, to_clamped = _clamp(DEFAULT_TIMEOUT, TIMEOUT_RANGE[0], TIMEOUT_RANGE[1],
                                     DEFAULT_TIMEOUT)
        ua = _text(_input(args, "user_agent")) or DEFAULT_UA
        if qps_clamped or cc_clamped or to_clamped:
            warnings.append("数值参数超出安全区间已自动夹逼：QPS=%d 并发=%d 超时=%d"
                            % (qps, concurrency, timeout))

        # ---------- 5) 组装边界快照与上下文 ----------
        scope_snapshot = {
            "version": task_id,
            "domains": domains + wildcards,
            "exact_domains": domains,
            "wildcard_domains": wildcards,
            "ip_ranges": ip_ranges,
            "url_prefixes": ["https://%s/" % d for d in domains],
            "exclude": {"paths": exclude_paths, "patterns": []},
            "window": window,
            "max_depth": 2,
            "max_concurrency": concurrency,
            "max_requests_per_run": 500,
            "rate_limit_qps": qps,
            "request_timeout": timeout,
            "user_agent": ua,
            "blocked_methods": BLOCKED_METHODS.split(","),
            "default_tier": "T0",
            "active_assets": list(domains),
            "tier2_assets": [],
            "source_schedule_text": _text(_input(args, "schedule")),
        }
        if scope_snapshot["active_assets"]:
            warnings.append("精确域名已列入 T1 受控探测白名单（被动档不变，主动档仍关闭）")

        sensitive_rules = {
            "version": task_id,
            "keywords": keywords,
            "regex": regex_rules,
            "file_types": [t.lower().lstrip(".") for t in filetypes],
            "samples": [sample_hint] if sample_hint else [],
            "whitelist": [],
            "masking": "partial",
            "sources": {"keywords": kw_src, "file_types": ft_src, "regex": re_src},
        }

        summary = ("授权确认通过；目标：精确域名 %d、通配 %d、IP 段 %d；排除路径 %d 条；时间窗 %s；"
                   "敏感规则：关键词 %d（%s）、正则 %d（%s）、文件类型 %d（%s）；限速 %d qps"
                   % (len(domains), len(wildcards), len(ip_ranges), len(exclude_paths), window,
                      len(keywords), kw_src, len(regex_rules), re_src,
                      len(sensitive_rules["file_types"]), ft_src, qps))
        audit.append({"ts": _now(), "action": "scope_build",
                      "target": ",".join(domains + wildcards), "result": "OK"})

        _log("[策略校验] %s | %.2fs" % (summary, time.time() - started))
        return {"result_key": json.dumps({
            "status": "OK", "error_code": 0, "error_message": "",
            "task_id": task_id,
            "scope_snapshot": scope_snapshot,
            "sensitive_rules": sensitive_rules,
            "alert_channel": _text(_input(args, "alert_channel")),
            "audit_log": audit, "warnings": warnings, "summary": summary,
        }, ensure_ascii=False)}
    except Exception as exc:
        _log("[策略校验] 执行异常：%s" % exc)
        return _deny("INVALID_INPUT", "策略校验执行异常：%s" % exc,
                     "策略校验执行异常，已终止执行。", audit)
