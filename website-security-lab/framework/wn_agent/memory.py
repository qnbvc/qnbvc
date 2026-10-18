"""基线与误报记忆（对应架构板块 5/6 的基线库、误报知识库）。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, content_hash, now_iso


class MemoryStore:
    """本地 JSON 存储；生产环境可替换为 PostgreSQL + 对象存储。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = {"baselines": {}, "false_positives": {}, "open_findings": {}}
        if self.path.exists():
            self.data.update(json.loads(self.path.read_text(encoding="utf-8")))

    def get_baseline(self, url: str) -> dict[str, Any] | None:
        return self.data["baselines"].get(url)

    def set_baseline(self, url: str, text: str, links: Iterable[str]) -> None:
        self.data["baselines"][url] = {
            "content_hash": content_hash(text),
            "text": text[:200_000],
            "links": sorted(set(links)),
            "updated_at": now_iso(),
        }

    def is_false_positive(self, dedup_key: str) -> bool:
        return dedup_key in self.data["false_positives"]

    def mark_false_positive(self, dedup_key: str, reason: str) -> None:
        self.data["false_positives"][dedup_key] = {"reason": reason, "ts": now_iso()}

    def update_lifecycle(self, findings: list[Finding]) -> dict[str, list[str]]:
        """基线与复测状态机：新增 / 复现 / 已修复。"""

        previous: dict[str, str] = self.data.get("open_findings", {})
        current = {f.dedup_key: f.title for f in findings}
        changes: dict[str, list[str]] = {"new": [], "reopened": [], "fixed": []}
        for key, title in current.items():
            changes["reopened" if key in previous else "new"].append(title)
        for key, title in previous.items():
            if key not in current:
                changes["fixed"].append(title)
        self.data["open_findings"] = current
        return changes

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
