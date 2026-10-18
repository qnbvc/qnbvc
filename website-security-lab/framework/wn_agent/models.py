"""统一数据模型与风险分级（对应架构板块 5）。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


class FindingType(str, Enum):
    """三类检测域 + 漏洞 / 弱配置。"""

    VULN = "vuln"            # 常见漏洞
    MISCONFIG = "misconfig"  # 弱配置
    TAMPER = "tamper"        # 页面篡改
    MALWARE = "malware"      # 挂马 / 恶意外链
    LEAK = "leak"            # 敏感信息泄露


class Tier(str, Enum):
    """安全档位：默认只允许 T0，T1 需按资产显式开启，T2 默认全局关闭。"""

    T0 = "T0"  # 被动采集：只读、无 payload、状态不变
    T1 = "T1"  # 受控探测：特定路径/非入侵模板，限速 + 时间窗
    T2 = "T2"  # 主动验证：可能改变状态，默认禁止


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FIXED = "fixed"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH: 0.70,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.18,
    Severity.INFO: 0.05,
}

# 风险分 → 告警等级
LEVEL_THRESHOLDS = ((0.60, "P0"), (0.38, "P1"), (0.15, "P2"))


def normalize_url(url: str) -> str:
    """URL 归一化：小写 scheme/host、去 fragment、查询参数排序、去尾部斜杠噪声。"""

    parts = urlsplit(url)
    path = re.sub(r"/{2,}", "/", parts.path) or "/"
    if path.endswith("/index.html"):          # 首页两种写法归一为同一页面
        path = path[: -len("index.html")]
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()


def content_hash(text: str) -> str:
    """结构化文本哈希：忽略空白噪声，用于基线对比。"""

    normalized = re.sub(r"\s+", " ", text).strip()
    return sha1(normalized)


@dataclass
class Asset:
    value: str                       # 域名 / IP / URL
    kind: str = "domain"             # domain | ip | url
    fingerprint: dict[str, str] = field(default_factory=dict)
    criticality: float = 0.5         # 资产重要性 0~1
    alive: bool = True
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class Page:
    url: str
    status: int = 200
    title: str = ""
    content_hash: str = ""
    depth: int = 0
    parent: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """证据：任何报告条目都必须可回溯到证据。"""

    kind: str          # request_response | diff | screenshot | match_context
    summary: str        # 已脱敏的摘要
    raw_ref: str = ""   # 原始证据的存储位置（本地路径 / 对象存储 key）


@dataclass
class Finding:
    """统一风险条目：所有工具输出都收敛到该模型后，再进入去重/验证/分级管线。"""

    asset: str
    url: str
    ftype: FindingType
    rule_id: str
    title: str
    severity: Severity
    tool: str = ""
    tier: Tier = Tier.T0
    location: str = ""
    cwe: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.60          # 置信度 0~1
    reachability: float = 1.0         # 可达性 0~1
    asset_criticality: float = 0.5    # 资产重要性 0~1
    impact: str = ""
    remediation: str = ""
    status: Status = Status.NEW
    first_seen: str = ""
    last_seen: str = ""
    sources: list[str] = field(default_factory=list)  # 命中该条目的全部工具
    verified: bool = False
    verify_hint: str = ""  # 非破坏性二次确证时，需要再次在页面上命中的片段

    # ---------- 派生属性 ----------

    @property
    def dedup_key(self) -> str:
        """跨工具去重键：同资产 + 同类型 + 同规则 + 同位置 → 视为同一条。"""

        raw = "|".join(
            [normalize_url(self.url), self.ftype.value, self.rule_id, self.location.strip().lower()]
        )
        return sha1(raw)[:16]

    @property
    def risk_score(self) -> float:
        """风险分 = 严重度 × 可达性 × 资产重要性 × 置信度 的归一化组合。"""

        sev = SEVERITY_WEIGHT[self.severity]
        reach = 0.5 + 0.5 * max(0.0, min(1.0, self.reachability))
        crit = 0.6 + 0.4 * max(0.0, min(1.0, self.asset_criticality))
        conf = 0.5 + 0.5 * max(0.0, min(1.0, self.confidence))
        return round(sev * reach * crit * conf, 4)

    @property
    def level(self) -> str:
        score = self.risk_score
        for threshold, level in LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return "P3"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ftype"] = self.ftype.value
        data["severity"] = self.severity.value
        data["tier"] = self.tier.value
        data["status"] = self.status.value
        data["dedup_key"] = self.dedup_key
        data["risk_score"] = self.risk_score
        data["level"] = self.level
        return data


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def verification_confidence(base: float, corroborating_tools: int, verified: bool) -> float:
    """置信度修正：多工具互证 + 二次确证 → 提升；单工具特征命中 → 保守。"""

    conf = base
    if corroborating_tools >= 2:
        conf += 0.20
    if verified:
        conf += 0.15
    return round(min(conf, 0.98), 2)
