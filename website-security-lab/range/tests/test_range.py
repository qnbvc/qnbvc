from __future__ import annotations

import http.client
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "range"))
sys.path.insert(0, str(ROOT / "framework"))

import server  # noqa: E402
from wn_agent.cli import build_agent  # noqa: E402
from wn_agent.models import FindingType  # noqa: E402

os.environ.setdefault("LAB_QUIET", "1")


class LabTests(unittest.TestCase):
    def setUp(self) -> None:
        server.STATE.set("clean")
        self.token = "unit-test-token"
        self.httpd = server.make_server("127.0.0.1", 0, self.token)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self) -> None:
        server.STATE.set("clean")
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)

    def _get(self, path: str) -> tuple[int, dict[str, str], bytes]:
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, dict(response.headers), response.read()

    def _toggle(self, action: str, token: str | None = None) -> int:
        headers = {"X-Lab-Token": token} if token else {}
        request = urllib.request.Request(
            f"{self.base}/__lab/{action}", method="POST", headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_clean_site_has_security_headers(self) -> None:
        status, headers, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("政务服务".encode("utf-8"), body)

    def test_weak_site_omits_security_headers(self) -> None:
        status, headers, body = self._get("/weak/")
        self.assertEqual(status, 200)
        self.assertNotIn("X-Frame-Options", headers)
        self.assertIn("测试后台".encode("utf-8"), body)

    def test_backup_is_a_valid_zip(self) -> None:
        status, _, body = self._get("/backup.zip")
        self.assertEqual(status, 200)
        archive = zipfile.ZipFile(io.BytesIO(body))
        self.assertIn("backup.sql", archive.namelist())

    def test_control_requires_token(self) -> None:
        self.assertEqual(self._toggle("tamper"), 403)
        self.assertEqual(server.STATE.mode, "clean")
        self.assertEqual(self._toggle("tamper", self.token), 200)
        self.assertEqual(server.STATE.mode, "tampered")
        _, _, body = self._get("/")
        self.assertIn(b"badcdn.invalid", body)
        self.assertEqual(self._toggle("restore", self.token), 200)
        self.assertEqual(server.STATE.mode, "clean")

    def test_path_traversal_is_blocked(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.httpd.server_address[1], timeout=5
        )
        connection.request("GET", "/%2e%2e/server.py")
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 403)
        connection.close()

    def test_control_api_can_be_disabled(self) -> None:
        disabled = server.make_server("127.0.0.1", 0, "unused", control_enabled=False)
        thread = threading.Thread(target=disabled.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{disabled.server_address[1]}/__lab/tamper",
                method="POST",
                headers={"X-Lab-Token": "unused"},
            )
            with self.assertRaises(urllib.error.HTTPError) as context:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(context.exception.code, 404)
        finally:
            disabled.shutdown()
            disabled.server_close()
            thread.join(timeout=3)

    def test_http_agent_baseline_and_tamper_retest(self) -> None:
        netloc = self.base.split("://", 1)[1]
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

            first = build_agent(config_path, None, memory_path, http=True).run(self.base + "/")
            first_types = {finding.ftype for finding in first["findings"]}
            self.assertIn(FindingType.LEAK, first_types)
            self.assertIn(FindingType.MISCONFIG, first_types)
            self.assertIn(FindingType.VULN, first_types)
            self.assertNotIn(FindingType.TAMPER, first_types)

            self.assertEqual(self._toggle("tamper", self.token), 200)
            second = build_agent(config_path, None, memory_path, http=True).run(self.base + "/")
            second_types = {finding.ftype for finding in second["findings"]}
            self.assertIn(FindingType.TAMPER, second_types)
            self.assertIn(FindingType.MALWARE, second_types)
            self.assertGreaterEqual(len(second["changes"]["new"]), 1)


if __name__ == "__main__":
    unittest.main()
