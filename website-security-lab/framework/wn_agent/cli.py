"""命令行入口：离线演示 / 单次巡检。

用法：
    python -m wn_agent.cli --demo                 # 离线演示（两轮：建基线 → 发现篡改）
    python -m wn_agent.cli --site <目录> --url <URL> --out <目录>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .agent import InspectorAgent
from .fetcher import HttpFetcher, LocalFetcher
from .gate import AuditLog, ComplianceError, Gate
from .memory import MemoryStore
from .models import Tier
from .report import summarize, write_outputs
from .tools import build_default_registry

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = BASE_DIR / "config" / "authorization.example.json"


def build_agent(config_path: str | Path, site_root: str | Path | None, memory_path: str | Path,
                audit_path: str | Path | None = None, *, http: bool = False) -> InspectorAgent:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    audit = AuditLog(audit_path)
    gate = Gate(config, audit=audit)
    if http:
        user_agent = config.get("rate_limit", {}).get(
            "user_agent", "SecurityInspector/1.0 (+authorized-scan)")
        fetcher = HttpFetcher(gate, user_agent)
    else:
        if site_root is None:
            raise ValueError("LocalFetcher requires --site")
        fetcher = LocalFetcher(site_root, gate=gate)
    memory = MemoryStore(memory_path)
    return InspectorAgent(config, fetcher, memory, build_default_registry())


def run_once(site_root: str | Path, url: str, config_path: str | Path,
             memory_path: str | Path, out_dir: str | Path, name: str,
             audit_path: str | Path | None = None, *, http: bool = False) -> dict[str, Any]:
    agent = build_agent(config_path, site_root, memory_path, audit_path, http=http)
    result = agent.run(url)
    paths = write_outputs(result, out_dir, name)
    stats = summarize(result["findings"])
    print(f"[{name}] 页面 {len(result['pages'])} 个 / 请求 {result['request_count']} 次 / "
          f"原始命中 {result['raw_count']} → 去重后 {stats['total']} 条 "
          f"（验证后排除 {result['excluded_false_positives']} 条未复现项） "
          f"（P0 {stats['by_level']['P0']}，P1 {stats['by_level']['P1']}，"
          f"P2 {stats['by_level']['P2']}，P3 {stats['by_level']['P3']}）")
    for finding in result["findings"]:
        print(f"    - [{finding.level}] {finding.title} "
              f"({finding.url}) 来源={','.join(finding.sources)}")
    for level, path in paths.items():
        print(f"    报告({level})：{path}")
    return result


def demonstrate_scope_rejection(config_path: str | Path, audit_path: str | Path) -> None:
    """演示授权闸门：范围外目标与未授权档位都会被拦截并留痕。"""

    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    gate = Gate(config, audit=AuditLog(audit_path))
    print("--- 合规闸门演示 ---")
    cases = (
        ("https://not-authorized.example.com/", Tier.T0, "范围外域名"),
        ("https://www.example.gov.cn/", Tier.T1, "在范围内但未开启 T1 受控探测"),
        ("https://portal.example.gov.cn/api/personal/list", Tier.T0, "命中排除路径"),
        ("https://portal.example.gov.cn/", Tier.T0, "范围内 + 授权档位，应当放行"),
    )
    for url, tier, note in cases:
        try:
            gate.check(url, tier=tier, action="fetch", tool="demo")
            print(f"    放行：{url}（{tier.value}）—— {note}")
        except ComplianceError as exc:
            print(f"    拦截：{url}（{tier.value}）—— {note} → {type(exc).__name__}: {exc}")


def run_demo(out_dir: str | Path, config_path: str | Path = DEFAULT_CONFIG) -> None:
    out = Path(out_dir)
    memory_path = out / "memory-demo.json"
    audit_path = out / "audit.jsonl"
    if memory_path.exists():
        memory_path.unlink()          # 演示需要干净起点
    if audit_path.exists():
        audit_path.unlink()
    url = "https://portal.example.gov.cn/"

    print("=== 第一轮：建立基线（首次巡检不产出篡改结论） ===")
    run_once(BASE_DIR / "demo_site", url, config_path, memory_path, out, "report-pass1", audit_path)

    print()
    print("=== 第二轮：站点发生变更后复测（应命中篡改 + 挂马 + 基线对比） ===")
    run_once(BASE_DIR / "demo_site_after_tamper", url, config_path, memory_path, out,
             "report-pass2", audit_path)

    print()
    demonstrate_scope_rejection(config_path, audit_path)
    print()
    print(f"完整报告与审计日志见：{out}")


def main(argv: list[str] | None = None) -> int:
    try:                                  # Windows 控制台默认 GBK，统一切到 UTF-8
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="网站安全智能巡检智能体（骨架实现）")
    parser.add_argument("--demo", action="store_true", help="运行离线两轮演示")
    parser.add_argument("--site", default=str(BASE_DIR / "demo_site"), help="本地站点目录")
    parser.add_argument("--url", default="https://portal.example.gov.cn/", help="巡检入口 URL")
    parser.add_argument("--http", action="store_true",
                        help="通过 HTTP 实际访问 --url（默认使用 --site 的离线快照）")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="授权与策略配置")
    parser.add_argument("--memory", default="out/memory.json", help="基线与误报存储")
    parser.add_argument("--out", default="out", help="报告输出目录")
    parser.add_argument("--name", default="report", help="报告文件名前缀")
    parser.add_argument("--validate-config", default=None,
                        help="执行子流程① 的配置校验（⑥ 校验 + ⑨ 规则编译）后退出")
    args = parser.parse_args(argv)

    if args.validate_config:
        from .intake import validate_config_file

        report = validate_config_file(args.validate_config)
        print(report.render())
        return 0 if report.ok else 1
    if args.demo or len(sys.argv) == 1:
        run_demo(args.out, args.config)
        return 0
    run_once(args.site, args.url, args.config, args.memory, args.out, args.name,
             Path(args.out) / "audit.jsonl", http=args.http)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
