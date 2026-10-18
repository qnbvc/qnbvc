"""子流程① 两个代码节点的回归测试：⑥ 输入校验 与 ⑨ 规则编译。"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from wn_agent.cli import DEFAULT_CONFIG
from wn_agent.intake import (ConfigValidator, check_cron, compile_sensitive_rules,
                             sample_fingerprint, validate_config_file)


def base_config() -> dict:
    return {
        "authorization": {
            "id": "AUTH-2026-0912-001",
            "owner": "某单位安全负责人",
            "valid_from": "2026-09-01",
            "valid_until": "2026-12-31",
            "document": "auth.pdf",
        },
        "scope": {
            "domains": ["portal.example.gov.cn", "*.example.gov.cn"],
            "ip_ranges": ["203.0.113.0/24"],
            "url_prefixes": ["https://portal.example.gov.cn/"],
            "exclude": {"paths": ["/admin/export"], "patterns": []},
            "max_depth": 2,
            "max_concurrency": 4,
            "max_requests_per_run": 20000,
        },
        "schedule": {"cron": "0 2 * * *", "window": "02:00-05:00", "freeze_dates": []},
        "rate_limit": {"per_domain_qps": 5, "global_qps": 20},
        "safety": {"default_tier": "T0", "active_assets": ["portal.example.gov.cn"],
                   "allow_active_tier": [], "deny_actions": ["bruteforce", "sqli_dump",
                                                             "file_upload", "dos"]},
        "sensitive_rules": {
            "keywords": ["内部资料"],
            "regex": [{"name": "手机号", "pattern": "(?<!\\d)1[3-9]\\d{9}(?!\\d)"}],
            "file_types": ["csv", "docx"],
            "samples": ["PROJECT-INTERNAL-ONLY-2026"],
            "whitelist": ["13800000000"],
        },
    }


def codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


class TestConfigValidator(unittest.TestCase):
    def test_example_config_passes(self) -> None:
        report = validate_config_file(DEFAULT_CONFIG)
        self.assertTrue(report.ok, report.render())
        self.assertEqual(report.compiled["regex"], 3)

    def test_bare_wildcard_rejected(self) -> None:
        config = base_config()
        config["scope"]["domains"] = ["*"]
        report = ConfigValidator(config).validate()
        self.assertFalse(report.ok)
        self.assertIn("ERR-AUTH-002", codes(report))

    def test_invalid_cidr_rejected(self) -> None:
        config = base_config()
        config["scope"]["ip_ranges"] = ["203.0.113.0/33"]
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-SCOPE-001", codes(report))

    def test_http_url_prefix_rejected(self) -> None:
        config = base_config()
        config["scope"]["url_prefixes"] = ["http://portal.example.gov.cn/"]
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-SCOPE-002", codes(report))

    def test_value_out_of_range(self) -> None:
        config = base_config()
        config["scope"]["max_concurrency"] = 999
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-SCOPE-005", codes(report))

    def test_invalid_cron_rejected(self) -> None:
        config = base_config()
        config["schedule"]["cron"] = "0 25 * * *"
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-SCHED-001", codes(report))
        self.assertIsNone(check_cron("*/15 0 1,15 * 1-5"))
        self.assertIsNotNone(check_cron("0 25 * * *"))
        self.assertIsNotNone(check_cron("0 2 * *"))

    def test_invalid_time_window(self) -> None:
        config = base_config()
        config["schedule"]["window"] = "25:00-26:00"
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-SCHED-002", codes(report))

    def test_unsupported_file_type(self) -> None:
        config = base_config()
        config["sensitive_rules"]["file_types"] = ["exe"]
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-RULE-005", codes(report))

    def test_short_keyword_warns(self) -> None:
        config = base_config()
        config["sensitive_rules"]["keywords"] = ["的"]
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-RULE-001", codes(report))

    def test_keyword_whitelist_conflict(self) -> None:
        config = base_config()
        config["sensitive_rules"]["keywords"] = ["13800000000"]
        config["sensitive_rules"]["whitelist"] = ["13800000000"]
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-RULE-004", codes(report))

    def test_tier2_requires_explicit_authorization(self) -> None:
        config = base_config()
        config["safety"]["allow_active_tier"] = ["portal.example.gov.cn"]
        config["safety"]["active_assets"] = []
        report = ConfigValidator(config).validate()
        self.assertIn("ERR-TIER-003", codes(report))

    def test_missing_owner_warns_only(self) -> None:
        config = base_config()
        config["authorization"]["owner"] = ""
        report = ConfigValidator(config).validate()
        self.assertTrue(report.ok)
        self.assertIn("ERR-AUTH-006", codes(report))


class TestRuleCompiler(unittest.TestCase):
    def test_compile_regex_and_fingerprint(self) -> None:
        rules = base_config()["sensitive_rules"]
        compiled, issues = compile_sensitive_rules(rules)
        self.assertEqual(len(compiled["regex"]), 1)
        self.assertEqual(compiled["regex"][0]["name"], "手机号")
        self.assertEqual(compiled["file_types"], ["csv", "docx"])
        self.assertEqual(len(compiled["samples"]), 1)
        self.assertEqual([i.code for i in issues], [])

    def test_broken_regex_is_reported(self) -> None:
        rules = {"regex": [{"name": "坏正则", "pattern": "([0-9"}]}
        compiled, issues = compile_sensitive_rules(rules)
        self.assertEqual(compiled["regex"], [])
        self.assertIn("ERR-RULE-002", {i.code for i in issues})

    def test_broad_pattern_warns(self) -> None:
        rules = {"regex": [{"name": "全匹配", "pattern": ".*"}]}
        _, issues = compile_sensitive_rules(rules)
        self.assertIn("ERR-RULE-003", {i.code for i in issues})

    def test_redos_pattern_rejected(self) -> None:
        rules = {"regex": [{"name": "回溯", "pattern": "(a+)+b"}]}
        compiled, issues = compile_sensitive_rules(rules)
        self.assertEqual(compiled["regex"], [])
        self.assertIn("ERR-RULE-006", {i.code for i in issues})

    def test_fingerprint_is_whitespace_insensitive(self) -> None:
        first = sample_fingerprint("内部资料 请勿 外传 编号 NB-2026-000123")
        second = sample_fingerprint("内部资料请勿外传编号NB-2026-000123")
        self.assertEqual(first, second)

    def test_whitelist_overlap_removed(self) -> None:
        rules = {"keywords": ["内部资料"], "whitelist": ["内部资料", "13800000000"]}
        compiled, issues = compile_sensitive_rules(rules)
        self.assertEqual(compiled["whitelist"], ["13800000000"])
        self.assertIn("ERR-RULE-004", {i.code for i in issues})


if __name__ == "__main__":
    unittest.main()
