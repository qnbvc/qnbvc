"""内容获取层：所有请求都先过授权闸门。

- LocalFetcher：离线演示用，把 URL 映射到本地目录（比赛现场网络受限也能跑通全流程）。
- HttpFetcher ：真实请求实现（urllib），默认限速 + 自定义 UA。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, unquote

from .gate import Gate
from .models import Tier


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed_ms: int = 0


class LocalFetcher:
    """把 https://host/path 映射到 <root>/path 的离线获取实现，用于演示与单元测试。"""

    def __init__(self, root: str | Path, gate: Gate | None = None) -> None:
        self.root = Path(root)
        self.gate = gate
        headers_file = self.root / "_headers.json"
        self._headers: dict[str, dict[str, str]] = (
            json.loads(headers_file.read_text(encoding="utf-8")) if headers_file.exists() else {}
        )

    def get(self, url: str, *, tier: Tier = Tier.T0, tool: str = "") -> Response:
        if self.gate is not None:
            self.gate.check(url, tier=tier, action="fetch", tool=tool)
        path = unquote(urlsplit(url).path)
        if path.endswith("/") or path == "":
            path += "index.html"
        target = (self.root / path.lstrip("/")).resolve()
        if not str(target).startswith(str(self.root.resolve())):
            return Response(url, 403, {}, "", 0)
        if not target.exists() or not target.is_file():
            return Response(url, 404, {}, "", 0)
        text = target.read_text(encoding="utf-8", errors="ignore")
        return Response(url, 200, dict(self._headers.get(path, {})), text, 0)


class HttpFetcher:
    """真实请求实现：授权检查 → 限速休眠 → 发起请求。"""

    def __init__(self, gate: Gate, user_agent: str, *, sleeper: Callable[[float], None] = time.sleep) -> None:
        self.gate = gate
        self.user_agent = user_agent
        self.sleeper = sleeper

    def get(self, url: str, *, tier: Tier = Tier.T0, tool: str = "") -> Response:
        wait = self.gate.check(url, tier=tier, action="fetch", tool=tool)
        if wait > 0:
            self.sleeper(min(wait, 30.0))
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                body = resp.read(2_000_000).decode("utf-8", "ignore")
                return Response(url, resp.status, dict(resp.headers), body,
                                int((time.monotonic() - started) * 1000))
        except urllib.error.HTTPError as exc:
            return Response(url, exc.code, dict(exc.headers or {}), "",
                            int((time.monotonic() - started) * 1000))
        except Exception as exc:  # 网络异常不阻塞整单
            return Response(url, 0, {}, f"<fetch-error>{exc}</fetch-error>",
                            int((time.monotonic() - started) * 1000))
