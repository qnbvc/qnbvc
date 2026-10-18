# coding=utf-8
"""③ 代码节点 · 合规闸门（校验 + 归一化 + 生成授权范围快照）。

输入（在"输入参数"里逐行引用交互节点的输出）：
    auth_targets        授权域名 / IP 段，英文逗号分隔
    scope_exclude       需要排除的路径，英文逗号分隔（可填"无"）
    schedule            巡检周期与时间窗（自然语言，如"每天 02:00 巡检，仅 02:00-05:00 发请求"）
    sensitive_keywords  敏感关键词，英文逗号分隔
    sensitive_regex     敏感正则，分号或换行分隔（正则里常含逗号，别用逗号分隔！）

输出（在"输出参数"里逐行声明同名参数）：
    scope_snapshot    String  授权范围快照（JSON），后续所有工具调用的边界依据
    sensitive_rules   String  敏感信息规则集（JSON）
    errors            String  错误清单（JSON 数组），非空表示校验未通过
    warnings          String  告警清单（JSON 数组），不影响继续执行
    valid             Number  1 = 通过，0 = 未通过
    summary           String  一句话结论，可直接展示给用户

注意：校验不通过属于"业务正常分支"，因此不抛异常，而是返回 valid=0 + errors，
      便于上游交互节点提示用户修改；只有代码本身出错才会抛出异常（配合"失败后返回"）。
"""

from runtime import Args

import ipaddress
import json
import re
import uuid

# ------------------------- 可调参数（演示默认值） -------------------------
DEFAULT_FILE_TYPES = ["pdf", "docx", "xlsx", "csv", "sql", "bak", "env", "log"]
DEFAULT_WINDOW = "02:00-05:00"
DEFAULT_TIER = "T0"
MAX_DEPTH = 2
MAX_CONCURRENCY = 4
MAX_REQUESTS_PER_RUN = 20000
# 演示用：把精确域名自动列入 T1 受控探测白名单；正式环境应改为人工确认后再填写
ENABLE_T1_FOR_EXACT_DOMAINS = True

# 输出模式：
#   "split"      → 6 个独立输出参数（下游引用更清晰）
#   "result_key" → 全部结果塞进 result_key 一个 JSON 字段（当前采用：面板输出参数配不动时的兜底）
OUTPUT_MODE = "result_key"
# ------------------------------------------------------------------------

DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
TIME_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
EMPTY_WORDS = {"", "无", "没有", "略", "none", "-", "/", "无。"}


# ------------------------------- 取值工具 -------------------------------

def _get(container, name, default=""):
    """args.input 可能是对象或 dict，这里两种取值方式都兼容，取不到就返回默认值。"""

    if container is None:
        return default
    value = getattr(container, name, None)
    if value is None and isinstance(container, dict):
        value = container.get(name)
    return default if value is None else value


def _text(value):
    """交互节点的答案可能是 {_question,_answer,_options} 结构，也可能是纯字符串。

    单选类问题的答案形如 {"_answer": {"A": "确认处置并归档"}, ...}，
    填空类问题形如 {"_answer": "无", ...}，这里统一取出可读文本。
    """

    if isinstance(value, dict):
        if "_answer" in value:
            return _text(value["_answer"])
        parts = [_text(item) for item in value.values()]
        return "、".join(part for part in parts if part)
    if isinstance(value, (list, tuple)):
        return "、".join(part for part in (_text(item) for item in value) if part)
    return "" if value is None else str(value)


def _split(text, seps=r"[,，;；\n\r\t]+"):
    """按指定分隔符拆分并去空白、去重、过滤"无"之类的占位词。"""

    text = _text(text)
    if not text:
        return []
    items, seen = [], set()
    for part in re.split(seps, str(text)):
        part = part.strip().strip("。;；,，")
        if part in EMPTY_WORDS or part in seen:
            continue
        seen.add(part)
        items.append(part)
    return items


# ------------------------------- 校验工具 -------------------------------

def _valid_domain(host):
    host = str(host or "")
    if ":" in host:                      # 容许 host:port 形式（测试环境常用）
        host = host.split(":")[0]
    if not host or len(host) > 253 or "." not in host:
        return False
    return all(DOMAIN_LABEL_RE.match(label) for label in host.rstrip(".").split("."))


def _classify_targets(targets, errors, warnings):
    """把输入目标分成 精确域名 / 通配域名 / IP 段 三类，并逐个校验。"""

    domains, wildcards, ip_ranges = [], [], []
    for item in targets:
        if "/" in item:                                  # 形如 203.0.113.0/24
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                errors.append({"code": "ERR-SCOPE-001",
                               "field": "auth_targets",
                               "message": "IP 段格式非法：%s（%s）" % (item, exc)})
                continue
            if network.prefixlen < 16:
                warnings.append({"code": "ERR-SCOPE-001", "field": "auth_targets",
                                 "message": "网段过大（/%d），建议收窄后再巡检" % network.prefixlen})
            ip_ranges.append(item)
        elif item.strip() == "*" or item.strip() == "*.":
            errors.append({"code": "ERR-AUTH-002", "field": "auth_targets",
                           "message": "禁止裸通配 *，必须写清二级域（如 *.example.gov.cn）"})
        elif item.startswith("*."):
            host = item[2:]
            if not _valid_domain(host):
                errors.append({"code": "ERR-AUTH-001", "field": "auth_targets",
                               "message": "通配域名格式非法：%s" % item})
            else:
                wildcards.append(item)
                warnings.append({"code": "WARN-SCOPE-006", "field": "auth_targets",
                                 "message": "%s 会显著扩大巡检面，请确认已在授权书范围内" % item})
        else:
            if "*" in item:
                errors.append({"code": "ERR-AUTH-002", "field": "auth_targets",
                               "message": "通配符只能出现在最左侧：%s" % item})
            elif not _valid_domain(item) and not _is_ip(item):
                errors.append({"code": "ERR-AUTH-001", "field": "auth_targets",
                               "message": "域名格式非法：%s" % item})
            else:
                domains.append(item)
    if not (domains or wildcards or ip_ranges):
        errors.append({"code": "ERR-AUTH-001", "field": "auth_targets",
                       "message": "至少需要一个授权域名或 IP 段"})
    return domains, wildcards, ip_ranges


def _is_ip(text):
    text = str(text or "")
    if text.count(":") == 1:             # 去掉 host:port 里的端口
        text = text.split(":")[0]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _normalize_exclude(raw, errors, warnings):
    paths = []
    for item in _split(raw):
        if not item.startswith("/"):
            warnings.append({"code": "WARN-SCOPE-004", "field": "scope_exclude",
                             "message": "%s 不是绝对路径，已自动补 '/' 为 /%s" % (item, item)})
            item = "/" + item.lstrip("/")
        paths.append(item)
    return paths


def _parse_window(text, errors, warnings):
    """从自然语言里抽时间窗：优先取 HH:MM-HH:MM；只给一个时间点则往后取 3 小时。"""

    normalized = str(text or "").replace("：", ":")
    range_match = re.search(r"(\d{1,2}:\d{2})\s*[-~至到]\s*(\d{1,2}:\d{2})", normalized)
    if range_match:
        window = "%02d:%s-%02d:%s" % (
            int(range_match.group(1).split(":")[0]), range_match.group(1).split(":")[1],
            int(range_match.group(2).split(":")[0]), range_match.group(2).split(":")[1])
        if TIME_WINDOW_RE.match(window):
            return window
        errors.append({"code": "ERR-SCHED-002", "field": "schedule",
                       "message": "时间窗越界或格式错误：%s" % window})
        return DEFAULT_WINDOW
    single = re.search(r"(\d{1,2}):(\d{2})", normalized)
    if single:
        start_hour = int(single.group(1))
        end_hour = min(start_hour + 3, 23)
        return "%02d:%s-%02d:%s" % (start_hour, single.group(2), end_hour, single.group(2))
    hour_only = re.search(r"(\d{1,2})\s*点", normalized)      # 支持"凌晨 3 点"这类口语表达
    if hour_only:
        start_hour = int(hour_only.group(1))
        if 0 <= start_hour <= 23:
            end_hour = min(start_hour + 3, 23)
            return "%02d:00-%02d:00" % (start_hour, end_hour)
    warnings.append({"code": "WARN-SCHED-001", "field": "schedule",
                     "message": "未识别到时间窗，已使用默认 %s，请确认" % DEFAULT_WINDOW})
    return DEFAULT_WINDOW


def _validate_keywords(raw, warnings):
    keywords = []
    for item in _split(raw):
        if len(item) < 2:
            warnings.append({"code": "ERR-RULE-001", "field": "sensitive_keywords",
                             "message": "关键词过短易误报，建议不少于 2 个字：%s" % item})
        keywords.append(item)
    return keywords


def _validate_regex(raw, errors, warnings):
    """正则用分号 / 换行分隔（正则里可能含逗号，所以不能用逗号拆）。"""

    compiled, index = [], 0
    for item in _split(raw, r"[;；\n\r]+"):
        index += 1
        name = "自定义规则%d" % index
        try:
            re.compile(item)
        except re.error as exc:
            errors.append({"code": "ERR-RULE-002", "field": "sensitive_regex",
                           "message": "第 %d 条正则编译失败：%s（%s）" % (index, item, exc)})
            continue
        if item in (".*", ".+") or len(item) > 500:
            warnings.append({"code": "ERR-RULE-003", "field": "sensitive_regex",
                             "message": "规则过宽易误报，建议增加前后缀限定：%s" % item[:40]})
        compiled.append({"name": name, "pattern": item})
    return compiled


# --------------------------------- 主逻辑 ---------------------------------

def handler(args: Args) -> dict:
    errors, warnings = [], []
    try:
        inp = getattr(args, "input", None)
        snapshot_version = "v%s-%s" % (
            __import__("time").strftime("%Y.%m.%d"), uuid.uuid4().hex[:6])

        # 1) 整体取值
        auth_targets = _text(_get(inp, "auth_targets"))
        scope_exclude = _text(_get(inp, "scope_exclude"))
        schedule_text = _text(_get(inp, "schedule"))
        keywords_raw = _text(_get(inp, "sensitive_keywords"))
        regex_raw = _text(_get(inp, "sensitive_regex"))

        # 2) 归一化 + 校验
        domains, wildcards, ip_ranges = _classify_targets(_split(auth_targets), errors, warnings)
        exclude_paths = _normalize_exclude(scope_exclude, errors, warnings)
        window = _parse_window(schedule_text, errors, warnings)
        keywords = _validate_keywords(keywords_raw, warnings)
        regex_rules = _validate_regex(regex_raw, errors, warnings)

        if not (keywords or regex_rules):
            warnings.append({"code": "WARN-RULE-001", "field": "sensitive_keywords",
                             "message": "未配置任何敏感关键词或正则，敏感信息检测维度将为空"})

        # 3) 组装授权范围快照（后续所有工具调用的唯一边界依据）
        active_assets = list(domains) if ENABLE_T1_FOR_EXACT_DOMAINS else []
        scope_snapshot = {
            "version": snapshot_version,
            "domains": domains + wildcards,
            "exact_domains": domains,
            "wildcard_domains": wildcards,
            "ip_ranges": ip_ranges,
            "url_prefixes": ["https://%s/" % d for d in domains],
            "exclude": {"paths": exclude_paths, "patterns": []},
            "max_depth": MAX_DEPTH,
            "max_concurrency": MAX_CONCURRENCY,
            "max_requests_per_run": MAX_REQUESTS_PER_RUN,
            "window": window,
            "freeze_dates": [],
            "default_tier": DEFAULT_TIER,
            "active_assets": active_assets,
            "tier2_assets": [],
            "source_text": str(schedule_text or ""),
        }
        if active_assets:
            warnings.append({"code": "WARN-TIER-001", "field": "active_assets",
                             "message": "已将精确域名列入 T1 受控探测白名单（被动档不变，主动档仍关闭）"})

        sensitive_rules = {
            "version": snapshot_version,
            "keywords": keywords,
            "regex": regex_rules,
            "file_types": list(DEFAULT_FILE_TYPES),
            "samples": [],
            "whitelist": [],
            "masking": "partial",
        }

        # 4) 汇总
        valid = 0 if errors else 1
        summary = ("授权目标：精确域名 %d 个、通配域名 %d 个、IP 段 %d 个；排除路径 %d 条；"
                   "时间窗 %s；敏感关键词 %d 个、正则 %d 条 → %s"
                   % (len(domains), len(wildcards), len(ip_ranges), len(exclude_paths),
                      window, len(keywords), len(regex_rules),
                      "校验通过" if valid else "校验未通过，请按错误提示修改"))
        if warnings:
            summary += "（%d 条告警）" % len(warnings)

        print("[合规闸门] %s | version=%s" % (summary, snapshot_version))   # 平台运行日志可见，便于排查

        payload = {
            "scope_snapshot": json.dumps(scope_snapshot, ensure_ascii=False),
            "sensitive_rules": json.dumps(sensitive_rules, ensure_ascii=False),
            "errors": json.dumps(errors, ensure_ascii=False),
            "warnings": json.dumps(warnings, ensure_ascii=False),
            "valid": valid,
            "summary": summary,
        }
        if OUTPUT_MODE == "result_key":     # 兜底模式：全部结果打包进一个字段
            return {"result_key": json.dumps(payload, ensure_ascii=False)}
        return dict(payload, result_key="ok" if valid else "invalid")
    except Exception as exc:                      # 代码自身异常：结构化返回，避免整条流程中断
        error_payload = {
            "scope_snapshot": "{}",
            "sensitive_rules": "{}",
            "errors": json.dumps([{"code": "ERR-CODE-000", "field": "-",
                                   "message": "代码节点执行异常：%s" % exc}], ensure_ascii=False),
            "warnings": "[]",
            "valid": 0,
            "summary": "配置校验执行异常，请检查输入参数是否已正确引用交互节点的输出。",
        }
        if OUTPUT_MODE == "result_key":
            return {"result_key": json.dumps(error_payload, ensure_ascii=False)}
        return dict(error_payload, result_key="error")
