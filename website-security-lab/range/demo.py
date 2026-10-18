#!/usr/bin/env python3
"""Run the complete baseline -> tamper -> retest loop against the synthetic lab."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "framework"))
sys.path.insert(0, str(ROOT / "range"))

import server  # noqa: E402
from wn_agent.cli import build_agent  # noqa: E402
from wn_agent.models import FindingType  # noqa: E402
from wn_agent.report import summarize  # noqa: E402


def _toggle(base: str, token: str, action: str) -> None:
    request = urllib.request.Request(
        f"{base}/__lab/{action}",
        method="POST",
        headers={"X-Lab-Token": token},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError(f"control API returned HTTP {response.status}")


def main() -> int:
    os.environ.setdefault("LAB_QUIET", "1")
    token = "local-demo-only"
    server.STATE.set("clean")
    httpd = server.make_server("127.0.0.1", 0, token)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    netloc = base.split("://", 1)[1]

    out_dir = ROOT / "range" / "out" / "demo"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            config = json.loads(
                (ROOT / "range" / "authorization.range.json").read_text(encoding="utf-8")
            )
            config["safety"]["active_assets"] = [netloc]
            config["asset_criticality"] = {netloc: 0.9}
            config["rate_limit"]["per_domain_qps"] = 100
            config["rate_limit"]["global_qps"] = 200
            config_path = Path(tmp) / "authorization.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            memory_path = Path(tmp) / "memory.json"

            print(f"demo target: {base}/")
            agent = build_agent(config_path, None, memory_path, http=True)
            first = agent.run(base + "/")
            first_types = {finding.ftype for finding in first["findings"]}
            print(
                f"pass 1: pages={len(first['pages'])} requests={first['request_count']} "
                f"raw={first['raw_count']} dedup={len(first['findings'])} "
                f"levels={summarize(first['findings'])['by_level']}"
            )
            if FindingType.TAMPER in first_types:
                raise AssertionError("first pass must only establish a baseline")

            _toggle(base, token, "tamper")
            time.sleep(0.1)
            agent2 = build_agent(config_path, None, memory_path, http=True)
            second = agent2.run(base + "/")
            second_types = {finding.ftype for finding in second["findings"]}
            print(
                f"pass 2: pages={len(second['pages'])} requests={second['request_count']} "
                f"raw={second['raw_count']} dedup={len(second['findings'])} "
                f"levels={summarize(second['findings'])['by_level']} "
                f"new={len(second['changes']['new'])}"
            )
            if FindingType.TAMPER not in second_types or FindingType.MALWARE not in second_types:
                raise AssertionError("tampered pass must report TAMPER and MALWARE")

            from wn_agent.report import write_outputs

            paths = write_outputs(second, out_dir, "range-pass2")
            print("reports:", ", ".join(str(path) for path in paths.values()))
            return 0
    finally:
        _toggle(base, token, "restore")
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
