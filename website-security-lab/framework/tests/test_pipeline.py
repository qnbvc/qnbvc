"""骨架实现的回归测试：合规闸门、去重、验证、端到端巡检。

运行方式（在 framework 目录下）：
    python -m unittest discover -s tests
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wn_agent.agent import Fuser, InspectorAgent, Verifier
from wn_agent.cli import DEFAULT_CONFIG, build_agent
from wn_agent.fetcher import LocalFetcher
from wn_agent.gate import AuditLog, ComplianceError, Gate, OutOfScope, TierNotAllowed
from wn_agent.memory import MemoryStore
from wn_agent.models import (Evidence, Finding, FindingType, Severity, Status, Tier,
                             normalize_url)
from wn_agent.tools import build_default_registry

BASE_DIR = Path(__file__).resolve().parent.parent
DEMO_SITE = BASE_DIR / "demo_site"
TAMPERED_SITE = BASE_DIR / "demo_site_after_tamper"
ENTRY_URL = "https://portal.example.gov.cn/"


def _test_config() -> dict:
    return {
        "authorization": {"id": "TEST-AUTH", "valid_until": "2099-01-01"},
        "scope": {
            "domains": ["a.example.cn", "*.example.cn"],
            "exclude": {"paths": ["/private"], "patterns": []},
            "max_depth": 1,
            "max_requests_per_run": 50,
        },
        "schedule": {"window": "00:00-23:59", "freeze_dates": []},
        "rate_limit": {"per_domain_qps": 100, "global_qps": 100},
        "safety": {"default_tier": "T0", "active_assets": [], "allow_active_tier": []},
    }


class TestGate(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = Gate(_test_config(), audit=AuditLog())

    def test_out_of_scope_rejected(self) -> None:
        with self.assertRaises(OutOfScope):
            self.gate.check("https://b.example.com/")
        self.assertEqual(len(self.gate.audit.rejected()), 1)

    def test_excluded_path_rejected(self) -> None:
        with self.assertRaises(OutOfScope):
            self.gate.check("https://a.example.cn/private/list")

    def test_tier_not_authorized(self) -> None:
        with self.assertRaises(TierNotAllowed):
            self.gate.check("https://a.example.cn/", tier=Tier.T1)

    def test_in_scope_allowed(self) -> None:
        self.gate.check("https://a.example.cn/")
        self.assertEqual(self.gate.request_count, 1)

    def test_expired_authorization(self) -> None:
        config = _test_config()
        config["authorization"]["valid_until"] = "2000-01-01"
        gate = Gate(config, audit=AuditLog())
        with self.assertRaises(ComplianceError):
            gate.check("https://a.example.cn/")


class TestModels(unittest.TestCase):
    def test_index_url_normalization(self) -> None:
        self.assertEqual(normalize_url("https://a.cn/"), normalize_url("https://a.cn/index.html"))

    def test_risk_level_mapping(self) -> None:
        critical = Finding("a", "https://a.cn/", FindingType.LEAK, "R1", "t",
                           Severity.CRITICAL, confidence=0.9, asset_criticality=0.9)
        low = Finding("a", "https://a.cn/", FindingType.MISCONFIG, "R2", "t", Severity.LOW,
                      confidence=0.4, asset_criticality=0.3)
        self.assertEqual(critical.level, "P0")
        self.assertEqual(low.level, "P3")
        self.assertGreater(critical.risk_score, low.risk_score)


class TestFuser(unittest.TestCase):
    def test_cross_tool_dedup(self) -> None:
        common = dict(asset="a", url="https://a.cn/x", ftype=FindingType.VULN,
                      rule_id="R1", title="t", location="body")
        first = Finding(severity=Severity.MEDIUM, tool="nuclei", confidence=0.6, **common)
        second = Finding(severity=Severity.HIGH, tool="nikto", confidence=0.7, **common)
        merged = Fuser().merge([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].sources, ["nikto", "nuclei"])
        self.assertEqual(merged[0].severity, Severity.HIGH)      # 取更严重者
        self.assertGreater(merged[0].confidence, 0.7)            # 多工具互证提升置信度

    def test_different_location_not_merged(self) -> None:
        base = dict(asset="a", url="https://a.cn/x", ftype=FindingType.LEAK,
                    rule_id="R1", title="t", severity=Severity.HIGH)
        merged = Fuser().merge([Finding(location="头部", tool="a", **base),
                                Finding(location="页脚", tool="b", **base)])
        self.assertEqual(len(merged), 2)


class TestVerifier(unittest.TestCase):
    def test_false_positive_when_not_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gate = Gate(_load_config(), audit=AuditLog())      # 使用演示站点所属的授权范围
            fetcher = LocalFetcher(DEMO_SITE, gate=gate)
            finding = Finding("a", ENTRY_URL, FindingType.LEAK, "R1", "t", Severity.HIGH,
                              tool="sensitive-scan", verify_hint="这里的内容不存在于页面",
                              evidence=[Evidence("match_context", "x")])
            Verifier(gate, fetcher).verify([finding])
            self.assertEqual(finding.status, Status.FALSE_POSITIVE)
            self.assertLess(finding.confidence, 0.3)


class TestEndToEnd(unittest.TestCase):
    """两轮巡检：第一轮建基线，第二轮（站点被篡改）应命中篡改与挂马。"""

    def test_two_pass_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            memory_path = Path(tmp) / "memory.json"
            agent = build_agent(DEFAULT_CONFIG, DEMO_SITE, memory_path)
            first = agent.run(ENTRY_URL)
            types = {f.ftype for f in first["findings"]}
            self.assertIn(FindingType.LEAK, types)
            self.assertIn(FindingType.MISCONFIG, types)
            self.assertIn(FindingType.VULN, types)
            self.assertNotIn(FindingType.TAMPER, types)      # 首次巡检只建基线
            self.assertGreater(first["raw_count"], len(first["findings"]))   # 去重确实发生

            agent2 = build_agent(DEFAULT_CONFIG, TAMPERED_SITE, memory_path)
            second = agent2.run(ENTRY_URL)
            second_types = {f.ftype for f in second["findings"]}
            self.assertIn(FindingType.TAMPER, second_types)
            self.assertIn(FindingType.MALWARE, second_types)
            self.assertGreaterEqual(len(second["changes"]["new"]), 1)
            titles = [f.title for f in second["findings"]]
            self.assertTrue(any("badcdn.top" in t for t in titles))

    def test_whitelist_suppresses_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agent = build_agent(DEFAULT_CONFIG, DEMO_SITE, Path(tmp) / "memory.json")
            result = agent.run(ENTRY_URL)
            evidence_text = " ".join(e.summary for f in result["findings"] for e in f.evidence)
            self.assertNotIn("13800000000", evidence_text)   # 白名单号码不应出现在证据中
            self.assertTrue(any("手机号" in finding.rule_id for finding in result["findings"]))


def _load_config() -> dict:
    import json

    return json.loads(Path(DEFAULT_CONFIG).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
