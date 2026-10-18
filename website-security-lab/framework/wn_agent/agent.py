"""智能体核心（对应架构板块 3）：规划 → 路由 → 编排 → 去重 → 验证 → 解释。"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from .gate import ComplianceError, Gate
from .memory import MemoryStore
from .models import (SEVERITY_WEIGHT, Finding, FindingType, Page, Status, Tier, content_hash,
                     normalize_url, now_iso, verification_confidence)
from .tools import ToolAdapter, ToolContext, ToolRegistry

TIER_SEQ = ("T0", "T1", "T2")

# 静态资源不作为"页面"抓取（它们由资源清单单独管理，后续可接入 JS/密钥扫描）
STATIC_SUFFIXES = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".woff", ".woff2", ".ttf", ".map")


@dataclass
class Subtask:
    """一个子任务：能力域 + 档位 + 目标粒度 + 选择理由（理由用于可解释性）。"""

    capability: str
    tier: Tier
    target: str          # page | asset
    reason: str


@dataclass
class Plan:
    asset: str
    subtasks: list[Subtask] = field(default_factory=list)


@dataclass
class ExecutionTrace:
    """执行留痕：用了哪个工具、跳过或失败的原因。"""

    entries: list[dict[str, str]] = field(default_factory=list)

    def add(self, tool: str, target: str, status: str, detail: str = "") -> None:
        self.entries.append({"tool": tool, "target": target, "status": status, "detail": detail})


class Planner:
    """规则驱动的规划器：输出子任务清单与可读的选择理由。"""

    def plan(self, asset: str, pages: list[Page], gate: Gate, memory: MemoryStore) -> Plan:
        plan = Plan(asset)
        plan.subtasks.append(Subtask(
            "misconfig", Tier.T0, "page",
            "站点存活且可获取响应，执行安全响应头与配置基线检查"))
        plan.subtasks.append(Subtask(
            "leak", Tier.T0, "page",
            "已配置敏感信息规则（关键词/正则/文件类型/样例），执行内容泄露检查"))
        plan.subtasks.append(Subtask(
            "malware", Tier.T0, "page",
            "执行外链白名单与挂马特征比对（含隐藏元素与混淆脚本）"))
        has_baseline = any(memory.get_baseline(p.url) for p in pages)
        plan.subtasks.append(Subtask(
            "tamper", Tier.T0, "page",
            "存在历史基线，执行内容完整性 diff"
            if has_baseline else "首次巡检：仅建立内容基线，本周期不产出篡改结论"))
        host = urlsplit(asset).netloc
        if gate.auth.tier_allowed(Tier.T1, host):
            plan.subtasks.append(Subtask(
                "vuln", Tier.T1, "asset",
                f"资产 {host} 已在授权白名单开启 T1 受控探测，执行备份文件与调试端点检查"))
        else:
            plan.subtasks.append(Subtask(
                "vuln", Tier.T1, "asset",
                f"资产 {host} 未开启 T1，跳过主动探测（保持被动档位）"))
        return plan


class Router:
    """工具路由：能力域 + 档位上限 → 具体工具。"""

    def __init__(self, registry: ToolRegistry, default_tier: Tier = Tier.T0) -> None:
        self.registry = registry
        self.default_tier = default_tier

    def route(self, subtask: Subtask) -> list[ToolAdapter]:
        max_tier = self.default_tier if subtask.tier is Tier.T0 else subtask.tier
        return self.registry.for_capability(subtask.capability, max_tier)


class Fuser:
    """结果融合：跨工具按 dedup_key 合并，保留全部来源与最强证据。"""

    def merge(self, findings: list[Finding]) -> list[Finding]:
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            groups.setdefault(finding.dedup_key, []).append(finding)
        merged: list[Finding] = []
        for items in groups.values():
            base = copy.deepcopy(items[0])
            for extra in items[1:]:
                if SEVERITY_WEIGHT[extra.severity] > SEVERITY_WEIGHT[base.severity]:
                    base.severity = extra.severity
                known = {e.summary for e in base.evidence}
                base.evidence.extend(e for e in extra.evidence if e.summary not in known)
                base.impact = base.impact or extra.impact
                base.remediation = base.remediation or extra.remediation
            base.sources = sorted({f.tool for f in items} | set(base.sources))
            base.tier = min((f.tier for f in items), key=lambda t: TIER_SEQ.index(t.value))
            base.verified = any(f.verified for f in items)
            base.confidence = verification_confidence(
                max(f.confidence for f in items), len(base.sources), base.verified)
            merged.append(base)
        merged.sort(key=lambda f: f.risk_score, reverse=True)
        return merged


class Verifier:
    """非破坏性二次确证：只做只读复采，不发送任何 payload。"""

    def __init__(self, gate: Gate, fetcher: Any) -> None:
        self.gate = gate
        self.fetcher = fetcher

    def verify(self, findings: list[Finding]) -> None:
        for finding in findings:
            if finding.ftype is FindingType.MISCONFIG:
                continue
            try:
                resp = self.fetcher.get(finding.url, tier=Tier.T0, tool="verifier")
            except ComplianceError:
                continue
            if resp.status != 200:
                continue
            if finding.ftype is FindingType.VULN:
                confirmed = True                      # 敏感文件仍可访问即确证
            elif finding.verify_hint:
                confirmed = finding.verify_hint in resp.text
            else:
                confirmed = finding.ftype in (FindingType.TAMPER, FindingType.LEAK)
            if confirmed:
                finding.verified = True
                finding.confidence = verification_confidence(
                    finding.confidence, len(finding.sources), True)
            else:
                finding.confidence = 0.2
                finding.status = Status.FALSE_POSITIVE
                finding.sources.append("verifier:未复现")


class Explainer:
    """补齐影响与修复建议，并给出 CWE 参考链接。"""

    DEFAULTS = {
        FindingType.MISCONFIG: (
            "配置层面防护不足，可能被用于点击劫持、内容注入或信息泄露。",
            "按基线补齐安全配置，并在网关统一收敛。"),
        FindingType.VULN: (
            "该暴露面可被匿名访问，可能直接导致数据或凭据泄露。",
            "下线或加固该资源，并补充访问控制与监控。"),
        FindingType.TAMPER: (
            "页面内容与基线不一致，可能被非授权修改或误发布。",
            "确认变更来源，非授权变更立即回滚。"),
        FindingType.MALWARE: (
            "疑似挂马或暗链，可能导致访问者被劫持或植入恶意内容。",
            "隔离并人工审计，清理后排查写入路径。"),
        FindingType.LEAK: (
            "敏感信息对外可见，存在合规与数据泄露风险。",
            "下线或脱敏该内容，并排查同类页面。"),
    }

    def explain(self, findings: list[Finding]) -> None:
        for finding in findings:
            impact, remediation = self.DEFAULTS[finding.ftype]
            finding.impact = finding.impact or impact
            finding.remediation = finding.remediation or remediation
            finding.last_seen = finding.last_seen or now_iso()

    @staticmethod
    def reference(finding: Finding) -> str:
        if finding.cwe.startswith("CWE-"):
            return f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[1]}.html"
        return ""


class InspectorAgent:
    """巡检智能体主控：发现 → 规划 → 执行 → 融合 → 验证 → 解释 → 基线 → 报告数据。"""

    def __init__(self, config: dict[str, Any], fetcher: Any, memory: MemoryStore,
                 registry: ToolRegistry, actor: str = "inspector") -> None:
        self.config = config
        self.fetcher = fetcher
        self.memory = memory
        self.registry = registry
        self.gate: Gate = getattr(fetcher, "gate", None) or Gate(config, actor=actor)
        self.actor = actor
        self.planner = Planner()
        self.router = Router(registry, self.gate.default_tier)
        self.fuser = Fuser()
        self.verifier = Verifier(self.gate, fetcher)
        self.explainer = Explainer()
        self.max_pages = int(config.get("scope", {}).get("max_depth", 2)) * 5 + 5

    def discover(self, start_url: str, trace: ExecutionTrace) -> list[Page]:
        """页面发现：同站 BFS，范围外的链接由闸门直接拦截。"""

        pages: list[Page] = []
        seen: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]
        max_depth = int(self.config.get("scope", {}).get("max_depth", 2))
        while queue and len(pages) < self.max_pages:
            url, depth = queue.pop(0)
            key = normalize_url(url)
            if key in seen:
                continue
            seen.add(key)
            try:
                resp = self.fetcher.get(url, tier=Tier.T0, tool="crawler")
            except ComplianceError as exc:
                trace.add("crawler", url, "blocked", str(exc))
                continue
            if resp.status != 200:
                continue
            body = resp.text
            page = Page(url=url, status=resp.status, content_hash=content_hash(body),
                        depth=depth, headers=resp.headers)
            page.links = self._same_site_links(url, body)
            page.resources = sorted(set(re.findall(
                r"""(?:src|href)\s*=\s*["']([^"']+\.(?:js|css|pdf|xlsx?|docx?|zip))["']""",
                body, re.I)))
            pages.append(page)
            if depth < max_depth:
                queue.extend((link, depth + 1) for link in page.links)
        return pages

    def _same_site_links(self, base: str, text: str) -> list[str]:
        host = urlsplit(base).netloc
        links = []
        for raw in re.findall(r"""href\s*=\s*["']([^"']+)["']""", text, re.I):
            if raw.startswith(("mailto:", "javascript:", "#")):
                continue
            absolute = urljoin(base, raw)
            parts = urlsplit(absolute)
            if parts.scheme in ("http", "https") and parts.netloc == host:
                if parts.path.lower().endswith(STATIC_SUFFIXES):
                    continue
                links.append(absolute.split("#")[0])
        return sorted(set(links))

    def run(self, start_url: str) -> dict[str, Any]:
        trace = ExecutionTrace()
        self.gate.audit.record(self.actor, "inspect_start", start_url, result="ok")
        body_cache: dict[str, str] = {}
        pages = self.discover_cached(start_url, trace, body_cache)
        host = urlsplit(start_url).netloc
        plan = self.planner.plan(start_url, pages, self.gate, self.memory)

        raw_findings: list[Finding] = []
        for subtask in plan.subtasks:
            tools = self.router.route(subtask)
            if not tools:
                trace.add("-", subtask.capability, "no_tool", subtask.reason)
                continue
            for tool in tools:
                for page in pages:
                    ctx = ToolContext(gate=self.gate, fetcher=self.fetcher, asset=host, page=page,
                                      rules={**self.config.get("sensitive_rules", {}),
                                             "trusted_domains": self.config.get("trusted_domains", [])},
                                      policy=self.config.get("safety", {}), memory=self.memory)
                    try:
                        produced = tool.run(ctx)
                    except ComplianceError as exc:
                        trace.add(tool.meta.name, page.url, "blocked", str(exc))
                        continue
                    except Exception as exc:      # 失败隔离：单工具失败不影响整单
                        trace.add(tool.meta.name, page.url, "error", repr(exc))
                        continue
                    trace.add(tool.meta.name, page.url, "ok", f"命中 {len(produced)} 条")
                    for finding in produced:
                        finding.asset_criticality = float(
                            self.config.get("asset_criticality", {}).get(host, 0.5))
                        raw_findings.append(finding)

        merged = self.fuser.merge(raw_findings)
        self.verifier.verify(merged)
        excluded = [f for f in merged if f.status is Status.FALSE_POSITIVE]
        merged = [f for f in merged if f.status is not Status.FALSE_POSITIVE]
        merged = [f for f in merged if not self.memory.is_false_positive(f.dedup_key)]
        self.explainer.explain(merged)

        for page in pages:
            self.memory.set_baseline(page.url, body_cache.get(normalize_url(page.url), ""), page.links)
        changes = self.memory.update_lifecycle(merged)
        self.memory.save()

        self.gate.audit.record(self.actor, "inspect_finish", start_url, result="ok",
                               detail=f"请求 {self.gate.request_count} 次，输出风险 {len(merged)} 条")
        return {
            "asset": host,
            "authorization": self.gate.auth.id,
            "finished_at": now_iso(),
            "pages": pages,
            "plan": plan,
            "findings": merged,
            "raw_count": len(raw_findings),
            "excluded_false_positives": len(excluded),
            "trace": trace.entries,
            "audit": self.gate.audit,
            "changes": changes,
            "request_count": self.gate.request_count,
        }

    def discover_cached(self, start_url: str, trace: ExecutionTrace,
                        cache: dict[str, str]) -> list[Page]:
        pages = self.discover(start_url, trace)
        for page in pages:
            try:
                cache[normalize_url(page.url)] = self.fetcher.get(
                    page.url, tier=Tier.T0, tool="baseline").text
            except ComplianceError:
                cache[normalize_url(page.url)] = ""
        return pages
