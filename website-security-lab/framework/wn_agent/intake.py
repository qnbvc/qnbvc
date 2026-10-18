"""子流程① 的两个「代码节点」实现。

⑥ 输入规范化与格式校验：域名/CIDR/URL 前缀/cron/时间窗/数值边界/文件类型/排除路径覆盖检查
⑨ 规则编译与冲突检测：正则编译、样例指纹、过宽规则告警、冲突与查重

用法：
    from wn_agent.intake import ConfigValidator, compile_sensitive_rules
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# 支持解析的文件类型（子流程⑤ 的文档抽取能力边界）
SUPPORTED_FILE_TYPES = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "json",
    "xml", "log", "sql", "bak", "env", "yml", "yaml", "zip", "rar", "7z", "md",
}

DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
CRON_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
TIME_WINDOW_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$")
AUTH_ID_RE = re.compile(r"^AUTH-\d{4}-\d{4}-\d{3}$")

# 视为"过宽"（高误报）的正则特征
BROAD_PATTERNS = (re.compile(r"^\.\*$"), re.compile(r"^\.\+$"), re.compile(r"^\[\s*\S?\s*\]$"))
REDOS_PATTERNS = (re.compile(r"\([^)]*[+*][^)]*\)[+*]"), re.compile(r"\(\.\*\)[+*]"))


@dataclass
class Issue:
    level: str        # error | warning
    code: str
    field: str
    message: str

    def render(self) -> str:
        tag = "ERROR" if self.level == "error" else "WARN "
        return f"[{tag}] {self.code} {self.field}: {self.message}"


@dataclass
class ValidationReport:
    issues: list[Issue] = field(default_factory=list)
    compiled: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, level: str, code: str, field_name: str, message: str) -> None:
        self.issues.append(Issue(level, code, field_name, message))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [i.__dict__ for i in self.errors],
            "warnings": [i.__dict__ for i in self.warnings],
            "compiled": self.compiled,
        }

    def render(self) -> str:
        lines = ["授权与配置校验报告",
                 "=" * 46,
                 f"结论：{'通过' if self.ok else '未通过'}"
                 f"（错误 {len(self.errors)} 条，告警 {len(self.warnings)} 条）", ""]
        if self.issues:
            lines.extend(i.render() for i in self.issues)
        else:
            lines.append("（无问题）")
        if self.compiled:
            lines.append("")
            lines.append("规则编译结果："
                         f"关键词 {self.compiled.get('keywords', 0)} 条、"
                         f"正则 {self.compiled.get('regex', 0)} 条、"
                         f"文件类型 {self.compiled.get('file_types', 0)} 类、"
                         f"样例指纹 {self.compiled.get('samples', 0)} 个、"
                         f"白名单 {self.compiled.get('whitelist', 0)} 条")
        return "\n".join(lines)


# ---------------------------------------------------------------- 基础校验函数

def valid_domain(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return all(DOMAIN_LABEL_RE.match(label) for label in host.rstrip(".").split("."))


def check_domain_pattern(pattern: str) -> str | None:
    pattern = pattern.strip()
    if not pattern:
        return "域名不能为空"
    if pattern in ("*", "*."):
        return "禁止裸通配 *：必须写清二级域（如 *.example.gov.cn）"
    if pattern.startswith("*."):
        return None if valid_domain(pattern[2:]) else "通配域名主体格式非法"
    if "*" in pattern:
        return "通配符只能出现在最左侧（*.example.gov.cn）"
    return None if valid_domain(pattern) else "域名格式非法"


def check_cidr(cidr: str) -> str | None:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return f"CIDR 格式非法（{exc}）"
    if network.prefixlen < 16:
        return f"网段过大（/{network.prefixlen}），范围超过 /16 需审批"
    return None


def check_cron(expr: str) -> str | None:
    fields = expr.split()
    if len(fields) != 5:
        return f"cron 需要 5 段（分 时 日 月 周），实际 {len(fields)} 段"
    for index, part_field in enumerate(fields):
        low, high = CRON_RANGES[index]
        for part in part_field.split(","):
            if "/" in part:
                base, _, step = part.partition("/")
                if not step.isdigit() or int(step) == 0:
                    return f"第 {index + 1} 段步长非法：{step}"
                part = base
            if part == "*":
                continue
            if "-" in part:
                start, _, end = part.partition("-")
                if not (start.isdigit() and end.isdigit()):
                    return f"第 {index + 1} 段区间非法：{part}"
                start, end = int(start), int(end)
                if start > end or start < low or end > high:
                    return f"第 {index + 1} 段区间越界：{part}（允许 {low}-{high}）"
                continue
            if not part.isdigit():
                return f"第 {index + 1} 段含非法字符：{part}"
            value = int(part)
            if value < low or value > high:
                return f"第 {index + 1} 段越界：{value}（允许 {low}-{high}）"
    return None


def normalize_text(text: str) -> str:
    """样例归一化：全角转半角 + 去空白，降低匹配噪声。"""

    normalized = unicodedata.normalize("NFKC", text)
    return re.sub(r"\s+", "", normalized)


def sample_fingerprint(text: str, shingle: int = 32, top: int = 64) -> list[str]:
    """样例指纹：归一化后滑窗分片 → 哈希集合（用于全网模糊比对）。"""

    normalized = normalize_text(text)
    if len(normalized) <= shingle:
        return [hashlib.sha1(normalized.encode()).hexdigest()[:16]]
    hashes = {hashlib.sha1(normalized[i:i + shingle].encode()).hexdigest()[:16]
              for i in range(len(normalized) - shingle + 1)}
    return sorted(hashes)[:top]


# ---------------------------------------------------------------- ⑥ 输入校验节点

class ConfigValidator:
    """⑥ 代码节点：输入规范化与格式校验（纯确定性，不依赖模型判断）。"""

    def __init__(self, config: dict[str, Any], *, base_dir: str | Path | None = None) -> None:
        self.config = config
        self.base_dir = Path(base_dir) if base_dir else None

    def validate(self) -> ValidationReport:
        report = ValidationReport()
        self._validate_authorization(report)
        self._validate_scope(report)
        self._validate_schedule(report)
        self._validate_safety(report)
        self._validate_sensitive(report)
        return report

    # ---- 授权信息 ----

    def _validate_authorization(self, report: ValidationReport) -> None:
        auth = self.config.get("authorization", {})
        if not auth:
            report.add("error", "ERR-AUTH-000", "authorization", "缺少授权信息")
            return
        auth_id = str(auth.get("id", ""))
        if auth_id and not AUTH_ID_RE.match(auth_id):
            report.add("warning", "ERR-AUTH-004", "authorization.id",
                       f"授权编号建议使用 AUTH-YYYY-MMDD-NNN 格式：{auth_id}")
        start, end = str(auth.get("valid_from", "")), str(auth.get("valid_until", ""))
        if not start or not end:
            report.add("error", "ERR-AUTH-003", "authorization.valid_until", "有效期起止必填")
        elif start > end:
            report.add("error", "ERR-AUTH-003", "authorization.valid_from",
                       f"有效期起止颠倒：{start} > {end}")
        if not auth.get("owner"):
            report.add("warning", "ERR-AUTH-006", "authorization.owner", "未填写责任人")
        document = auth.get("document")
        if not document:
            report.add("error", "ERR-AUTH-005", "authorization.document", "缺少授权书附件")
        elif self.base_dir is not None and not (self.base_dir / str(document)).exists():
            report.add("warning", "ERR-AUTH-005", "authorization.document",
                       f"未找到授权书附件：{document}")

    # ---- 巡检范围 ----

    def _validate_scope(self, report: ValidationReport) -> None:
        scope = self.config.get("scope", {})
        domains = list(scope.get("domains", []))
        if not domains and not scope.get("ip_ranges"):
            report.add("error", "ERR-AUTH-001", "scope.domains", "至少需要一个授权域名或 IP 段")
        for index, pattern in enumerate(domains):
            problem = check_domain_pattern(str(pattern))
            if problem:
                report.add("error", "ERR-AUTH-001" if "通配" not in problem else "ERR-AUTH-002",
                           f"scope.domains[{index}]", f"{pattern}：{problem}")
            elif str(pattern).startswith("*."):
                report.add("warning", "WARN-SCOPE-006", f"scope.domains[{index}]",
                           f"{pattern}：通配子域会显著扩大扫描面，请确认已在授权书范围内")

        prefixes = list(scope.get("url_prefixes", []))
        for index, prefix in enumerate(prefixes):
            parts = urlsplit(str(prefix))
            if parts.scheme != "https":
                report.add("error", "ERR-SCOPE-002", f"scope.url_prefixes[{index}]",
                           f"URL 前缀必须使用 https：{prefix}")
            host = parts.netloc.split(":")[0]
            covered = any(
                host.endswith("." + str(d)[2:]) if str(d).startswith("*.") else host == str(d)
                for d in domains
            )
            if domains and not covered:
                report.add("warning", "ERR-SCOPE-003", f"scope.url_prefixes[{index}]",
                           f"URL 前缀不属于已授权域名：{prefix}")

        for index, cidr in enumerate(scope.get("ip_ranges", [])):
            problem = check_cidr(str(cidr))
            if problem:
                report.add("error", "ERR-SCOPE-001", f"scope.ip_ranges[{index}]",
                           f"{cidr}：{problem}")

        for name, value, low, high in (
                ("max_depth", scope.get("max_depth", 2), 0, 5),
                ("max_concurrency", scope.get("max_concurrency", 4), 1, 32),
                ("max_requests_per_run", scope.get("max_requests_per_run", 20000), 100, 200000)):
            if not isinstance(value, int) or not low <= value <= high:
                report.add("error", "ERR-SCOPE-005", f"scope.{name}",
                           f"{value} 超出允许范围 {low}-{high}")

        for index, path in enumerate(scope.get("exclude", {}).get("paths", [])):
            if not str(path).startswith("/"):
                report.add("error", "ERR-SCOPE-004", f"scope.exclude.paths[{index}]",
                           f"排除路径必须以 / 开头：{path}")

    # ---- 调度 ----

    def _validate_schedule(self, report: ValidationReport) -> None:
        schedule = self.config.get("schedule", {})
        cron = str(schedule.get("cron", "")).strip()
        if not cron:
            report.add("warning", "ERR-SCHED-001", "schedule.cron", "未配置周期，仅支持手动触发")
        else:
            problem = check_cron(cron)
            if problem:
                report.add("error", "ERR-SCHED-001", "schedule.cron",
                           f"{cron}：{problem}（合法示例：0 2 * * *）")
        window = str(schedule.get("window", "")).strip()
        if window and not TIME_WINDOW_RE.match(window):
            report.add("error", "ERR-SCHED-002", "schedule.window",
                       f"时间窗格式应为 HH:MM-HH:MM：{window}")
        for index, freeze in enumerate(schedule.get("freeze_dates", [])):
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(freeze)):
                report.add("warning", "ERR-SCHED-003", f"schedule.freeze_dates[{index}]",
                           f"冻结期建议使用 YYYY-MM-DD：{freeze}")

    # ---- 档位与安全 ----

    def _validate_safety(self, report: ValidationReport) -> None:
        safety = self.config.get("safety", {})
        tier = str(safety.get("default_tier", "T0"))
        if tier not in ("T0", "T1", "T2"):
            report.add("error", "ERR-TIER-001", "safety.default_tier", f"未知档位：{tier}")
        if tier != "T0":
            report.add("warning", "ERR-TIER-002", "safety.default_tier",
                       f"默认档位为 {tier}，建议巡检默认停留在 T0 被动档")
        active = set(safety.get("active_assets", []))
        for index, asset in enumerate(safety.get("allow_active_tier", [])):
            if asset not in active:
                report.add("error", "ERR-TIER-003", f"safety.allow_active_tier[{index}]",
                           f"T2 资产 {asset} 未列入 active_assets，缺少显式授权")
        for index, asset in enumerate(active):
            if not any(check_domain_pattern(str(d)) is None and (
                    asset == str(d) or (str(d).startswith("*.") and str(asset).endswith(str(d)[1:]))
            ) for d in self.config.get("scope", {}).get("domains", [])):
                report.add("warning", "ERR-TIER-004", f"safety.active_assets[{index}]",
                           f"{asset} 不在授权域名列表中")
        denied = list(safety.get("deny_actions", []))
        for required in ("bruteforce", "sqli_dump", "file_upload", "dos"):
            if required not in denied:
                report.add("warning", "ERR-TIER-005", "safety.deny_actions",
                           f"建议把 {required} 加入禁用清单")

    # ---- 敏感规则（⑥ 部分：格式层） ----

    def _validate_sensitive(self, report: ValidationReport) -> None:
        rules = self.config.get("sensitive_rules", {})
        for index, keyword in enumerate(rules.get("keywords", [])):
            text = str(keyword)
            if len(text) < 2:
                report.add("warning", "ERR-RULE-001", f"sensitive_rules.keywords[{index}]",
                           f"关键词过短易误报：{text}")
        for index, item in enumerate(rules.get("regex", [])):
            pattern = str(item.get("pattern", ""))
            if not pattern:
                report.add("error", "ERR-RULE-002", f"sensitive_rules.regex[{index}]", "正则表达式为空")
                continue
            try:
                re.compile(pattern)
            except re.error as exc:
                report.add("error", "ERR-RULE-002", f"sensitive_rules.regex[{index}]",
                           f"{item.get('name', '未命名')}：正则编译失败（{exc}）")
        for index, file_type in enumerate(rules.get("file_types", [])):
            if str(file_type).lower().lstrip(".") not in SUPPORTED_FILE_TYPES:
                report.add("error", "ERR-RULE-005", f"sensitive_rules.file_types[{index}]",
                           f"不支持的文件类型：{file_type}")
        whitelist = {str(w) for w in rules.get("whitelist", [])}
        for index, keyword in enumerate(rules.get("keywords", [])):
            if str(keyword) in whitelist:
                report.add("error", "ERR-RULE-004", f"sensitive_rules.keywords[{index}]",
                           f"关键词与白名单冲突：{keyword}")


# ---------------------------------------------------------------- ⑨ 规则编译节点

def compile_sensitive_rules(rules: dict[str, Any], *, base_dir: str | Path | None = None
                            ) -> tuple[dict[str, Any], list[Issue]]:
    """⑨ 代码节点：把敏感规则草稿编译成可运行规则集，并给出冲突/过宽报告。"""

    issues: list[Issue] = []
    compiled: dict[str, Any] = {"keywords": [], "regex": [], "file_types": [],
                                "samples": {}, "whitelist": []}

    for keyword in rules.get("keywords", []):
        text = str(keyword).strip()
        if not text:
            continue
        if len(text) < 2 or re.fullmatch(r"\d{4,}", text):
            issues.append(Issue("warning", "ERR-RULE-003", "keywords",
                                f"规则过宽，可能产生大量误报：{text}"))
        if text not in compiled["keywords"]:
            compiled["keywords"].append(text)

    for item in rules.get("regex", []):
        name, pattern = str(item.get("name", "未命名")), str(item.get("pattern", ""))
        try:
            compiled_pattern = re.compile(pattern)
        except re.error as exc:
            issues.append(Issue("error", "ERR-RULE-002", f"regex[{name}]",
                                f"正则编译失败（{exc}）"))
            continue
        if any(broad.match(pattern) for broad in BROAD_PATTERNS):
            issues.append(Issue("warning", "ERR-RULE-003", f"regex[{name}]",
                                f"规则过宽（{pattern}），建议增加前后缀限定"))
        if any(redos.search(pattern) for redos in REDOS_PATTERNS):
            issues.append(Issue("error", "ERR-RULE-006", f"regex[{name}]",
                                "存在灾难性回溯风险（嵌套量词），请改写"))
            continue
        if len(pattern) > 500:
            issues.append(Issue("warning", "ERR-RULE-003", f"regex[{name}]",
                                "正则过长，建议拆分为多条规则"))
        compiled["regex"].append({"name": name, "pattern": pattern, "compiled": compiled_pattern})

    for file_type in rules.get("file_types", []):
        normalized = str(file_type).lower().lstrip(".")
        if normalized not in SUPPORTED_FILE_TYPES:
            issues.append(Issue("error", "ERR-RULE-005", "file_types",
                                f"不支持的文件类型：{file_type}"))
            continue
        if normalized not in compiled["file_types"]:
            compiled["file_types"].append(normalized)

    for index, sample in enumerate(rules.get("samples", [])):
        name = f"sample-{index + 1}"
        text = ""
        path = Path(sample)
        if base_dir is not None and not path.is_absolute():
            path = Path(base_dir) / path
        if path.exists() and path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            name = path.name
        else:
            text = str(sample)          # 未提供文件时按文本样例处理
        fingerprint = sample_fingerprint(text)
        compiled["samples"][name] = fingerprint
        if len(normalize_text(text)) < 16:
            issues.append(Issue("warning", "ERR-RULE-007", f"samples[{name}]",
                                "样例内容过短，指纹区分度低，建议提供完整样例文件"))

    whitelist = [str(w) for w in rules.get("whitelist", [])]
    overlap = set(whitelist) & {str(k) for k in rules.get("keywords", [])}
    for value in overlap:
        issues.append(Issue("error", "ERR-RULE-004", "whitelist",
                            f"白名单与关键词互斥冲突：{value}"))
    compiled["whitelist"] = [w for w in whitelist if w not in overlap]

    # 查重：与既有规则集比对（此处以本次输入内的重复为例）
    names = [item["name"] for item in compiled["regex"]]
    for name in {n for n in names if names.count(n) > 1}:
        issues.append(Issue("warning", "ERR-RULE-008", f"regex[{name}]",
                            "存在同名规则，建议合并或重命名"))
    return compiled, issues


def validate_config_file(path: str | Path) -> ValidationReport:
    config_path = Path(path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    report = ConfigValidator(config, base_dir=config_path.parent.parent).validate()
    compiled, issues = compile_sensitive_rules(config.get("sensitive_rules", {}),
                                               base_dir=config_path.parent.parent)
    report.issues.extend(issues)
    report.compiled = {
        "keywords": len(compiled["keywords"]),
        "regex": len(compiled["regex"]),
        "file_types": len(compiled["file_types"]),
        "samples": len(compiled["samples"]),
        "whitelist": len(compiled["whitelist"]),
    }
    return report
