"""工具适配器框架（对应架构板块 4）：新增工具只需实现 ToolAdapter + ToolMeta。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

from .fetcher import Response
from .gate import Gate
from .models import Finding, Page, Tier

TIER_ORDER = {Tier.T0: 0, Tier.T1: 1, Tier.T2: 2}


@dataclass(frozen=True)
class ToolMeta:
    """工具元数据：名称、能力域、安全档位、说明。"""

    name: str
    capability: str          # discover / vuln / misconfig / tamper / malware / leak
    tier: Tier
    description: str
    upstream: str = ""       # 对应的开源工具（便于爬取到"工具清单"）


@dataclass
class ToolContext:
    """一次工具调用的上下文。"""

    gate: Gate
    fetcher: Any
    asset: str
    page: Page
    rules: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    memory: Any = None

    def fetch(self, url: str, tier: Tier, tool: str) -> Response:
        return self.fetcher.get(url, tier=tier, tool=tool)


class ToolAdapter(Protocol):
    meta: ToolMeta

    def run(self, ctx: ToolContext) -> list[Finding]:
        ...


class ToolRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> ToolAdapter:
        if adapter.meta.name in self._adapters:
            raise ValueError(f"工具重复注册：{adapter.meta.name}")
        self._adapters[adapter.meta.name] = adapter
        return adapter

    def all(self) -> list[ToolAdapter]:
        return list(self._adapters.values())

    def for_capability(self, capability: str, max_tier: Tier = Tier.T0) -> list[ToolAdapter]:
        limit = TIER_ORDER[max_tier]
        return [
            a for a in self._adapters.values()
            if a.meta.capability == capability and TIER_ORDER[a.meta.tier] <= limit
        ]

    def describe(self) -> list[dict[str, str]]:
        return [{"name": a.meta.name, "capability": a.meta.capability,
                 "tier": a.meta.tier.value, "description": a.meta.description,
                 "upstream": a.meta.upstream} for a in self._adapters.values()]


def build_default_registry() -> ToolRegistry:
    from .builtin_tools import (ExposurePathTool, IntegrityTool, MalwareLinkTool,
                                SecurityHeadersTool, SensitiveScanTool)

    registry = ToolRegistry()
    for adapter in (SecurityHeadersTool(), ExposurePathTool(), SensitiveScanTool(),
                    IntegrityTool(), MalwareLinkTool()):
        registry.register(adapter)
    return registry
