#!/usr/bin/env python3
"""Synthetic website security lab for the inspection agent.

The lab is intentionally small and dependency-free. It serves:

* a clean portal and a tampered variant on the same URLs;
* synthetic sensitive files and a directory-listing endpoint;
* a weak-configuration area with deliberately missing security headers;
* a token-protected control API for switching between baseline and tampered.

All data is fake. The server only implements read-only site endpoints plus the
control API, so it cannot be used as a file-upload or command-execution target.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


BASE_DIR = Path(__file__).resolve().parent
CLEAN_DIR = BASE_DIR / "site" / "clean"
TAMPERED_DIR = BASE_DIR / "site" / "tampered"
LEAK_DIR = BASE_DIR / "site" / "leaks"
WEAK_DIR = BASE_DIR / "site" / "weak"

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

FAKE_BACKUP_SQL = """-- Synthetic lab data. Do not use in production.
CREATE TABLE staff (id INT, name VARCHAR(64), phone VARCHAR(20), id_card VARCHAR(32));
INSERT INTO staff VALUES
  (1, '测试甲', '13911112222', '110101199001011234'),
  (2, '测试乙', '13722223333', '110101199202022345');
INSERT INTO config VALUES ('access_key_id', 'AKIAIOSFODNN7EXAMPLE');
-- PROJECT-INTERNAL-ONLY-2026
"""


def _build_backup_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("backup.sql", FAKE_BACKUP_SQL)
        archive.writestr(
            "readme.txt",
            "Synthetic backup created for the authorized security lab only.\n",
        )
    return buffer.getvalue()


BACKUP_BYTES = _build_backup_zip()


class LabState:
    def __init__(self, initial: str = "clean") -> None:
        self._lock = threading.Lock()
        self._mode = "tampered" if initial == "tampered" else "clean"

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def set(self, mode: str) -> str:
        if mode not in {"clean", "tampered"}:
            raise ValueError("mode must be clean or tampered")
        with self._lock:
            self._mode = mode
            return self._mode


STATE = LabState()


def _safe_join(root: Path, relative: str) -> Path | None:
    """Resolve a URL path below root and reject traversal."""

    candidate = (root / relative.lstrip("/")).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    overrides = {
        ".yaml": "text/yaml; charset=utf-8",
        ".yml": "text/yaml; charset=utf-8",
        ".map": "application/json; charset=utf-8",
        ".env": "text/plain; charset=utf-8",
        ".log": "text/plain; charset=utf-8",
        ".zip": "application/zip",
    }
    return overrides.get(suffix, mimetypes.guess_type(str(path))[0] or "application/octet-stream")


class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabGateway"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    _weak = False

    def version_string(self) -> str:
        return "LabGateway/1.0.0" if self._weak else "LabGateway"

    def log_message(self, fmt: str, *args: object) -> None:
        if os.environ.get("LAB_QUIET", "").lower() in {"1", "true", "yes"}:
            return
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{stamp}] {self.client_address[0]} {fmt % args}", flush=True)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        self._dispatch(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler name
        self._dispatch(include_body=False)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        if not self.server.control_enabled:  # type: ignore[attr-defined]
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "control API disabled"})
            return
        parsed = urlsplit(self.path)
        if parsed.path not in {"/__lab/tamper", "/__lab/restore"}:
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
            return
        supplied = self.headers.get("X-Lab-Token", "")
        expected = self.server.control_token  # type: ignore[attr-defined]
        if not secrets.compare_digest(supplied, expected):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid lab control token"})
            return
        mode = "tampered" if parsed.path.endswith("/tamper") else "clean"
        STATE.set(mode)
        self._send_json(HTTPStatus.OK, {"ok": True, "state": mode})

    def _dispatch(self, *, include_body: bool) -> None:
        self._weak = False
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)

        if path == "/__lab/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "state": STATE.mode,
                    "synthetic": True,
                    "control": (
                        "POST /__lab/tamper or /__lab/restore with X-Lab-Token"
                        if self.server.control_enabled  # type: ignore[attr-defined]
                        else "disabled"
                    ),
                },
                include_body=include_body,
            )
            return

        if path in {"/robots.txt", "/sitemap.xml"}:
            self._send_dynamic_text(path, include_body=include_body)
            return

        if path == "/weak/api/debug":
            self._weak = True
            payload = {
                "app": "synthetic-admin",
                "debug": True,
                "environment": "lab",
                "database": {
                    "host": "db.lab.invalid",
                    "user": "lab_admin",
                    "password": "FAKE_DB_PASSWORD_NOT_REAL",
                },
                "sample_key": "AKIAIOSFODNN7EXAMPLE",
                "note": "Synthetic debug response. No real secrets are present.",
            }
            self._send_json(HTTPStatus.OK, payload, include_body=include_body)
            return

        if path == "/backup.zip":
            self._send_bytes(
                BACKUP_BYTES,
                "application/zip",
                include_body=include_body,
                extra_headers={"Content-Disposition": 'attachment; filename="backup.zip"'},
            )
            return

        if path == "/.env":
            self._serve_file(CLEAN_DIR / "lab-env.txt", include_body=include_body)
            return

        if path == "/.git/config":
            self._serve_file(CLEAN_DIR / "lab-git-config.txt", include_body=include_body)
            return

        if path.startswith("/weak/"):
            self._weak = True
            relative = path[len("/weak/") :]
            self._serve_from(WEAK_DIR, relative, include_body=include_body, allow_listing=True)
            return

        if path.startswith("/leaks/"):
            self._weak = True
            relative = path[len("/leaks/") :]
            self._serve_from(LEAK_DIR, relative, include_body=include_body, allow_listing=True)
            return

        relative = path.lstrip("/")
        if STATE.mode == "tampered":
            override_relative = relative if relative and not relative.endswith("/") else relative + "index.html"
            target = _safe_join(TAMPERED_DIR, override_relative)
            if target is not None and target.is_file():
                self._serve_file(target, include_body=include_body)
                return
        self._serve_from(CLEAN_DIR, relative, include_body=include_body, allow_listing=False)

    def _serve_from(
        self,
        root: Path,
        relative: str,
        *,
        include_body: bool,
        allow_listing: bool,
    ) -> None:
        target = _safe_join(root, relative)
        if target is None:
            self._send_error_page(HTTPStatus.FORBIDDEN, "path outside lab root", include_body)
            return
        if target.is_dir():
            index = target / "index.html"
            if index.is_file():
                self._serve_file(index, include_body=include_body)
                return
            if allow_listing:
                self._send_listing(target, include_body=include_body)
                return
            self._send_error_page(HTTPStatus.FORBIDDEN, "directory listing disabled", include_body)
            return
        if target.is_file():
            self._serve_file(target, include_body=include_body)
            return
        self._send_error_page(HTTPStatus.NOT_FOUND, "not found", include_body)

    def _serve_file(self, path: Path, *, include_body: bool) -> None:
        self._send_bytes(
            path.read_bytes(),
            _content_type(path),
            include_body=include_body,
        )

    def _send_listing(self, directory: Path, *, include_body: bool) -> None:
        entries = sorted(directory.iterdir(), key=lambda item: item.name.lower())
        items = []
        for entry in entries:
            name = html.escape(entry.name + ("/" if entry.is_dir() else ""))
            href = html.escape(entry.name + ("/" if entry.is_dir() else ""))
            items.append(f'<li><a href="{href}">{name}</a></li>')
        body = (
            "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
            "<title>Index of lab directory</title><h1>目录列表（故意暴露）</h1>"
            "<p>该目录列表用于验证弱配置检测，内容全部为合成数据。</p><ul>"
            + "".join(items)
            + "</ul></html>"
        ).encode("utf-8")
        self._send_bytes(body, "text/html; charset=utf-8", include_body=include_body)

    def _send_dynamic_text(self, path: str, *, include_body: bool) -> None:
        host = re.sub(r"[^A-Za-z0-9.:\-\[\]]", "", self.headers.get("Host", "127.0.0.1:8080"))
        host = host or "127.0.0.1:8080"
        origin = f"http://{host}"
        if path == "/robots.txt":
            body = (
                "User-agent: *\n"
                "Disallow: /weak/admin/\n"
                "Disallow: /leaks/\n"
                "Disallow: /files/\n"
                f"Sitemap: {origin}/sitemap.xml\n"
            ).encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            urls = [
                "/",
                "/news.html",
                "/about.html",
                "/weak/",
                "/weak/files/",
                "/leaks/",
                "/files/statistics.csv",
            ]
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                + "".join(f"<url><loc>{origin}{url}</loc></url>" for url in urls)
                + "</urlset>"
            ).encode("utf-8")
            content_type = "application/xml; charset=utf-8"
        self._send_bytes(body, content_type, include_body=include_body)

    def _send_error_page(self, status: HTTPStatus, message: str, include_body: bool) -> None:
        body = (
            "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
            f"<title>{status.value}</title><h1>{status.value} {html.escape(message)}</h1></html>"
        ).encode("utf-8")
        self._send_bytes(body, "text/html; charset=utf-8", status=status, include_body=include_body)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, object],
        *,
        include_body: bool = True,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._send_bytes(
            body,
            "application/json; charset=utf-8",
            status=status,
            include_body=include_body,
        )

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        include_body: bool,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if not self._weak:
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self, address: tuple[str, int], control_token: str, control_enabled: bool = True
    ) -> None:
        super().__init__(address, LabHandler)
        self.control_token = control_token
        self.control_enabled = control_enabled


def make_server(
    host: str, port: int, control_token: str, control_enabled: bool = True
) -> LabServer:
    return LabServer((host, port), control_token, control_enabled)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthetic website security lab")
    parser.add_argument("--host", default=os.environ.get("LAB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("LAB_PORT", "8080")))
    parser.add_argument(
        "--initial-state",
        choices=("clean", "tampered"),
        default=os.environ.get("LAB_INITIAL_STATE", "clean"),
    )
    parser.add_argument(
        "--no-control",
        action="store_true",
        help="disable /__lab/tamper and /__lab/restore (recommended for public demos)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    token = os.environ.get("LAB_CONTROL_TOKEN") or secrets.token_urlsafe(18)
    STATE.set(args.initial_state)
    server = make_server(args.host, args.port, token, control_enabled=not args.no_control)
    shown_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    print(f"Lab target : http://{shown_host}:{args.port}/", flush=True)
    print(f"Initial    : {STATE.mode}", flush=True)
    print(f"Control    : {token if not args.no_control else 'disabled'}", flush=True)
    print("Synthetic data only. Expose it through a private tailnet or an authenticated tunnel.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping lab.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        print(f"Unable to start lab: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
