"""授权闸门（对应架构板块 1）：范围校验、限速、时间窗、档位管控、审计日志。

设计要点：闸门位于**所有出站请求之前**，工具适配器无法绕过它。
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .models import Tier, now_iso


class ComplianceError(RuntimeError):
    """合规拦截基类：被拦截的请求不允许继续执行。"""


class OutOfScope(ComplianceError):
    pass


class AuthorizationExpired(ComplianceError):
    pass


class OutsideTimeWindow(ComplianceError):
    pass


class TierNotAllowed(ComplianceError):
    pass


class DeniedAction(ComplianceError):
    pass


class BudgetExceeded(ComplianceError):
    pass


@dataclass
class Authorization:
    id: str
    owner: str = ""
    valid_from: str = ""
    valid_until: str = ""
    document: str = ""
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    url_prefixes: list[str] = field(default_factory=list)
    allow_active_assets: list[str] = field(default_factory=list)   # T1/T2 白名单
    allow_tier2_assets: list[str] = field(default_factory=list)    # T2 需二次显式授权

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Authorization":
        scope = data.get("scope", {})
        safety = data.get("safety", {})
        auth = data.get("authorization", {})
        return cls(
            id=auth.get("id", "UNKNOWN"),
            owner=auth.get("owner", ""),
            valid_from=auth.get("valid_from", ""),
            valid_until=auth.get("valid_until", ""),
            document=auth.get("document", ""),
            domains=list(scope.get("domains", [])),
            ip_ranges=list(scope.get("ip_ranges", [])),
            url_prefixes=list(scope.get("url_prefixes", [])),
            allow_active_assets=list(safety.get("active_assets", [])),
            allow_tier2_assets=list(safety.get("allow_active_tier", [])),
        )

    def is_expired(self, today: date) -> bool:
        if not self.valid_until:
            return False
        return today > date.fromisoformat(self.valid_until)

    # ---------- 范围判定 ----------

    def host_allowed(self, host: str) -> bool:
        host = host.split(":")[0].lower()
        try:  # IP 目标按网段判定
            ip = ipaddress.ip_address(host)
            return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in self.ip_ranges)
        except ValueError:
            pass
        for pattern in self.domains:
            pattern = pattern.lower()
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if host.endswith("." + suffix):   # 通配符仅覆盖子域
                    return True
            elif host == pattern:
                return True
        return False

    def url_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        if not self.host_allowed(parts.netloc):
            return False
        if self.url_prefixes and not any(url.startswith(p) for p in self.url_prefixes):
            return False
        return True

    def tier_allowed(self, tier: Tier, asset: str) -> bool:
        if tier is Tier.T0:
            return True
        if tier is Tier.T1:
            return asset in self.allow_active_assets
        return asset in self.allow_tier2_assets


class TokenBucket:
    """令牌桶限速器（域名级 + 全局级双层）。"""

    def __init__(self, rate_per_sec: float, burst: int | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = float(burst if burst is not None else max(1, int(rate_per_sec)))
        self.tokens = self.capacity
        self.clock = clock
        self.updated = clock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now

    def take(self) -> float:
        """尝试取一个令牌，返回需要等待的秒数（0 表示立即可发）。"""

        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return 0.0
        return round((1.0 - self.tokens) / self.rate, 3)

    def refund(self) -> None:
        self._refill()
        self.tokens = min(self.capacity, self.tokens + 1.0)


@dataclass
class AuditEntry:
    ts: str
    actor: str
    action: str
    target: str
    tool: str = ""
    result: str = ""
    detail: str = ""


class AuditLog:
    """审计日志：谁、何时、对哪个资产、做了什么、结果如何（可落盘为 JSONL）。"""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[AuditEntry] = []

    def record(self, actor: str, action: str, target: str, tool: str = "",
               result: str = "ok", detail: str = "") -> AuditEntry:
        entry = AuditEntry(now_iso(), actor, action, target, tool, result, detail)
        self.entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.__dict__, ensure_ascii=False) + "\n")
        return entry

    def rejected(self) -> list[AuditEntry]:
        return [e for e in self.entries if e.result == "rejected"]


class Gate:
    """授权闸门：所有请求出站前必须通过 check()。"""

    def __init__(self, config: dict[str, Any], *, actor: str = "inspector",
                 clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = datetime.now,
                 audit: AuditLog | None = None) -> None:
        self.auth = Authorization.from_dict(config)
        scope = config.get("scope", {})
        rate = config.get("rate_limit", {})
        sched = config.get("schedule", {})
        safety = config.get("safety", {})

        self.exclude_paths = list(scope.get("exclude", {}).get("paths", []))
        self.exclude_patterns = list(scope.get("exclude", {}).get("patterns", []))
        self.max_depth = int(scope.get("max_depth", 3))
        self.max_requests = int(scope.get("max_requests_per_run", 10_000))
        self.follow_offsite = bool(scope.get("follow_redirects_offsite", False))
        self.window = sched.get("window", "")
        self.freeze_dates = list(sched.get("freeze_dates", []))
        self.denied_actions = set(safety.get("deny_actions", []))
        self.default_tier = Tier(safety.get("default_tier", "T0"))

        self.clock = clock
        self._now = now
        self.actor = actor
        self.audit = audit or AuditLog()
        self.global_bucket = TokenBucket(rate.get("global_qps", 20), clock=clock)
        self._domain_buckets: dict[str, TokenBucket] = {}
        self._domain_rate = float(rate.get("per_domain_qps", 5))
        self.request_count = 0

    # ---------- 校验 ----------

    def check(self, url: str, *, tier: Tier = Tier.T0, action: str = "fetch",
              tool: str = "") -> float:
        """不通过则抛 ComplianceError；通过则计入预算与限速令牌，返回建议等待秒数。"""

        if self.auth.is_expired(self._now().date()):
            self.audit.record(self.actor, action, url, tool, "rejected", "授权已过期")
            raise AuthorizationExpired(f"授权 {self.auth.id} 已过期，拒绝执行")

        if not self.auth.url_allowed(url):
            self.audit.record(self.actor, action, url, tool, "rejected", "目标不在授权范围内")
            raise OutOfScope(f"目标不在授权范围内：{url}")

        parts = urlsplit(url)
        if any(fnmatch.fnmatch(parts.path, pat) or parts.path.startswith(pat)
               for pat in self.exclude_paths):
            self.audit.record(self.actor, action, url, tool, "rejected", "命中排除路径")
            raise OutOfScope(f"命中巡检范围排除路径：{parts.path}")
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(url, pattern):
                self.audit.record(self.actor, action, url, tool, "rejected", "命中排除规则")
                raise OutOfScope(f"命中巡检范围排除规则：{pattern}")

        if action in self.denied_actions:
            self.audit.record(self.actor, action, url, tool, "rejected", "该动作在禁用清单中")
            raise DeniedAction(f"动作 {action} 属于默认禁用清单，不允许执行")

        asset = parts.netloc
        if not self.auth.tier_allowed(tier, asset):
            self.audit.record(self.actor, action, url, tool, "rejected", f"档位 {tier.value} 未授权")
            raise TierNotAllowed(f"资产 {asset} 未获授权档位 {tier.value}")

        self._check_window(url, action, tool)

        if self.request_count >= self.max_requests:
            self.audit.record(self.actor, action, url, tool, "rejected", "超出单次巡检请求预算")
            raise BudgetExceeded(f"超出单次巡检请求预算 {self.max_requests}")

        self.request_count += 1
        wait = self.wait_time(url)
        self.audit.record(self.actor, action, url, tool, "ok",
                          f"已授权；限速等待 {wait}s；累计请求 {self.request_count}")
        return wait

    def _check_window(self, url: str, action: str, tool: str) -> None:
        if self.freeze_dates and self._now().date().isoformat() in self.freeze_dates:
            self.audit.record(self.actor, action, url, tool, "rejected", "命中冻结期")
            raise OutsideTimeWindow("当前处于冻结期，拒绝执行")
        if not self.window:
            return
        start_s, _, end_s = self.window.partition("-")
        now_hm = self._now().strftime("%H:%M")
        if start_s <= end_s:
            inside = start_s <= now_hm <= end_s
        else:                        # 跨零点窗口，如 23:00-02:00
            inside = now_hm >= start_s or now_hm <= end_s
        if not inside:
            self.audit.record(self.actor, action, url, tool, "rejected", "不在巡检时间窗内")
            raise OutsideTimeWindow(f"当前时间 {now_hm} 不在巡检时间窗 {self.window} 内")

    # ---------- 限速 ----------

    def wait_time(self, url: str) -> float:
        host = urlsplit(url).netloc
        bucket = self._domain_buckets.setdefault(host, TokenBucket(self._domain_rate, clock=self.clock))
        wait = max(bucket.take(), self.global_bucket.take())
        return wait

