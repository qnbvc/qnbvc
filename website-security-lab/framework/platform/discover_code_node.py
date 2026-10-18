# coding=utf-8
"""④ 代码节点 · 资产与页面发现（授权范围内的同站爬虫，非破坏性）。

输入：
    gate_payload   ③ 合规闸门输出的 JSON 字符串
                   （在"输入参数"里：值类型 引用 → 选 ③.result_key）

输出（result_key，JSON 字符串）：
    {
      "pages":   [{"url","status","depth","content_hash","title","headers","links","resources","text"}],
      "assets":  [{"host","pages","status_codes"}],
      "stats":   {"pages","requests","seconds","seed_urls"},
      "blocked": [{"url","reason"}],
      "errors":  [{"url","error"}]
    }

合规约束（写死在代码里，上层无法绕过）：
    1. 只请求授权范围内的主机（精确域名 / 通配子域 / IP 段）；
    2. 命中排除路径或排除规则的一律不发请求，并记入 blocked；
    3. 同域请求间隔限速，单次巡检有请求预算与页面数上限；
    4. 只发 GET，带自定义 UA；重定向落点若不在授权范围内则丢弃内容；
    5. 不做任何写操作、不提交表单、不携带凭据；可按需遵守 robots.txt。
"""

from runtime import Args

import fnmatch
import gzip
import hashlib
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

# ------------------------- 可调参数 -------------------------
MAX_PAGES = 25                 # 单次巡检最多抓取页面数
MAX_DEPTH = 2                  # 默认爬取深度（可被授权配置覆盖）
REQUEST_TIMEOUT = 10           # 单请求超时（秒）
DELAY_PER_HOST = 0.5           # 同域请求间隔（秒）—— 限速
MAX_TEXT_CHARS = 8000          # 每页正文入库长度（过长截断，够做关键词/正则/外链检测）
USER_AGENT = "SecurityInspector/1.0 (+authorized-scan; contact=secops@example.gov.cn)"
RESPECT_ROBOTS = True          # 是否遵守 robots.txt（合规建议开启）
INSECURE_TLS = False           # 是否忽略证书错误（默认不忽略）
STATIC_SUFFIXES = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webp")
# -----------------------------------------------------------

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([\w-]+)", re.I)
ROBOTS_LINE_RE = re.compile(r"^\s*(user-agent|disallow|allow)\s*:\s*(.*)$", re.I)
KEEP_HEADERS = ("server", "content-type", "content-security-policy", "x-frame-options",
                "strict-transport-security", "x-content-type-options", "referrer-policy")


# ------------------------------ 基础工具 ------------------------------

def _input(args, name, default=""):
    inp = getattr(args, "input", None)
    value = getattr(inp, name, None) if inp is not None else None
    if value is None and isinstance(inp, dict):
        value = inp.get(name)
    return default if value is None else value


def _content_hash(text):
    """结构化文本哈希：忽略空白噪声，用于后续与基线比对。"""

    return hashlib.sha1(re.sub(r"\s+", " ", text).strip().encode("utf-8", "ignore")).hexdigest()


def _unwrap(raw, default=None):
    """剥掉平台"引用"上游输出时包的 {"result_key": <内层 JSON>} 外壳（最多 4 层）。

    平台把上游节点的输出当作 `{"result_key": "<该节点 result_key 的值>"}` 传下来，
    所以任何接收上游 payload 的节点都要先剥壳，否则取不到里面的字段。
    """

    payload = raw
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return default if default is not None else {}
    for _ in range(4):
        if isinstance(payload, dict) and "result_key" in payload:
            inner = payload["result_key"]
            if isinstance(inner, str):
                try:
                    inner = json.loads(inner)
                except Exception:
                    break
            if isinstance(inner, (dict, list)):
                payload = inner
                continue
        break
    return payload if payload is not None else (default if default is not None else {})


def _normalize_url(url):
    """URL 归一化：折叠重复斜杠，并把 /index.html 视作目录首页（避免同一页面被算两次）。"""

    parts = urlsplit(url)
    path = re.sub(r"/{2,}", "/", parts.path) or "/"
    if path.endswith("/index.html"):
        path = path[: -len("index.html")]
    return "%s://%s%s" % (parts.scheme, parts.netloc, path)


def _decode(raw, headers):
    """按响应头/内容猜编码，中文站点常见 utf-8 与 gb18030。"""

    charset = ""
    match = CHARSET_RE.search(headers.get("Content-Type", "") or "")
    if match:
        charset = match.group(1)
    for encoding in (charset, "utf-8", "gb18030", "latin-1"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "ignore")


def _http_get(url, timeout=REQUEST_TIMEOUT):
    """只发 GET；返回 (status, headers, text, final_url)。status=0 表示请求失败。"""

    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
    })
    context = None
    if INSECURE_TLS:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            raw = resp.read(3_000_000)
            headers = dict(resp.headers)
            if headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return resp.status, headers, _decode(raw, headers), resp.geturl()
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = _decode(exc.read(20000), dict(exc.headers or {}))
        except Exception:
            pass
        return exc.code, dict(exc.headers or {}), body, url
    except Exception as exc:
        return 0, {}, "", "%s | %s" % (url, exc)


# ------------------------------ 合规判定 ------------------------------

class Scope:
    """授权范围：所有请求出站前都要过这里的判定。"""

    def __init__(self, snapshot):
        self.domains = [str(d).lower() for d in snapshot.get("domains", [])]
        self.ip_ranges = [str(c) for c in snapshot.get("ip_ranges", [])]
        exclude = snapshot.get("exclude", {}) or {}
        self.exclude_paths = [str(p) for p in exclude.get("paths", [])]
        self.exclude_patterns = [str(p) for p in exclude.get("patterns", [])]
        self.max_depth = int(snapshot.get("max_depth") or MAX_DEPTH)
        self.budget = int(snapshot.get("max_requests_per_run") or 500)

    def host_allowed(self, host):
        host = str(host or "").split(":")[0].lower()
        if not host:
            return False
        for pattern in self.domains:
            if pattern.startswith("*."):
                if host.endswith("." + pattern[2:]):
                    return True
            elif host == pattern:
                return True
        for cidr in self.ip_ranges:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def url_allowed(self, url):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not self.host_allowed(parts.netloc):
            return False, "目标不在授权范围内"
        for path in self.exclude_paths:
            if path and parts.path.startswith(path):
                return False, "命中排除路径 %s" % path
        for pattern in self.exclude_patterns:
            if pattern and fnmatch.fnmatch(url, pattern):
                return False, "命中排除规则 %s" % pattern
        return True, ""


def _load_robots(scope):
    """取授权域名的 robots.txt，返回 {host: [(allow, path)]}；取不到视为不限制。"""

    hosts = []
    for pattern in scope.domains:
        if pattern.startswith("*."):
            hosts.append("www." + pattern[2:])
        else:
            hosts.append(pattern)
    rules = {}
    for host in hosts:
        status, _, text, _ = _http_get("https://%s/robots.txt" % host)
        if status != 200 or not text:
            continue
        entries, active = [], False
        for line in text.splitlines():
            match = ROBOTS_LINE_RE.match(line)
            if not match:
                continue
            key, value = match.group(1).lower(), match.group(2).strip()
            if key == "user-agent":
                active = value == "*" or "inspector" in value.lower()
            elif active and key in ("allow", "disallow") and value:
                entries.append((key == "allow", value))
        rules[host] = entries
    return rules


def _robots_allows(rules, url):
    parts = urlsplit(url)
    entries = rules.get(parts.netloc.split(":")[0])
    if not entries:
        return True
    verdict, matched_len = True, -1
    for allow, path in entries:
        if path and path != "/" and parts.path.startswith(path) and len(path) > matched_len:
            verdict, matched_len = allow, len(path)
    return verdict


# ------------------------------ 链接提取 ------------------------------

def _extract_links(base, text):
    """在完整 HTML 上抽取同站页面链接与资源链接（不受正文截断影响）。"""

    base_host = urlsplit(base).netloc
    pages, resources = [], []
    for attr, raw in re.findall(r"""(href|src)\s*=\s*["']([^"']+)["']""", text, re.I):
        if raw.startswith(("mailto:", "javascript:", "tel:", "#", "data:")):
            continue
        absolute = urljoin(base, raw.strip())
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https") or parts.netloc != base_host:
            continue                      # 只爬同站；站外链接留给检测环节判定
        clean = absolute.split("#")[0]
        if parts.path.lower().endswith(STATIC_SUFFIXES) or attr.lower() == "src":
            resources.append(clean)
        else:
            pages.append(clean)
    return sorted(set(pages)), sorted(set(resources))


def _fail(message):
    print("[资产发现] " + message)
    return {"result_key": json.dumps(
        {"pages": [], "assets": [], "stats": {}, "blocked": [],
         "errors": [{"url": "-", "error": message}]}, ensure_ascii=False)}


# ------------------------------- 主逻辑 -------------------------------

def handler(args: Args) -> dict:
    errors, blocked = [], []
    started = time.time()
    try:
        payload = _unwrap(_input(args, "gate_payload"))
        snapshot = payload.get("scope_snapshot", "{}")
        if isinstance(snapshot, str):
            snapshot = json.loads(snapshot)
        if str(payload.get("valid", 1)) not in ("1", "True", "true"):
            return _fail("③ 合规闸门校验未通过，已拒绝执行资产发现：%s" % payload.get("errors", ""))
        if not (snapshot.get("domains") or snapshot.get("ip_ranges")):
            return _fail("授权范围为空：请先让 ③ 合规闸门校验通过再执行资产发现")

        scope = Scope(snapshot)
        rules = _load_robots(scope) if RESPECT_ROBOTS else {}
        seeds = ["https://%s/" % d for d in (snapshot.get("exact_domains") or snapshot.get("domains", []))
                 if not str(d).startswith("*.")]
        if not seeds:
            return _fail("没有可用于发现的精确域名（通配域需先做子域枚举）")

        pages, assets = [], {}
        queue, seen, requests = [(url, 0) for url in seeds], set(), 0
        while queue and len(pages) < MAX_PAGES and requests < scope.budget:
            url, depth = queue.pop(0)
            key = _normalize_url(url)
            if key in seen:
                continue
            seen.add(key)
            allowed, reason = scope.url_allowed(url)
            if not allowed:
                blocked.append({"url": url, "reason": reason})
                continue
            if RESPECT_ROBOTS and not _robots_allows(rules, url):
                blocked.append({"url": url, "reason": "robots.txt 禁止抓取"})
                continue

            requests += 1
            time.sleep(DELAY_PER_HOST)                       # 限速
            status, headers, text, final_url = _http_get(url)
            if status == 0 and url.startswith("https://"):    # https 失败退回 http，并记为风险信号
                status, headers, text, final_url = _http_get("http://" + url[len("https://"):])
                if status:
                    errors.append({"url": url,
                                   "error": "HTTPS 不可用，已回退 HTTP（建议整改为全站 HTTPS）"})
            if status == 0:
                errors.append({"url": url, "error": str(final_url)})
                continue

            final_host = urlsplit(final_url).netloc if final_url.startswith("http") else ""
            if final_host and not scope.host_allowed(final_host):
                blocked.append({"url": url, "reason": "重定向落点 %s 不在授权范围内" % final_host})
                continue

            final_norm = _normalize_url((final_url or url).split("#")[0])
            if final_norm in seen and final_norm != key:
                continue                     # https→http 回退后与已抓页面重复，不再入册
            seen.add(final_norm)

            page_links, page_resources = _extract_links(final_url or url, text)
            title = TITLE_RE.search(text)
            pages.append({
                "url": _normalize_url((final_url or url).split("#")[0]),
                "status": status,
                "depth": depth,
                "content_hash": _content_hash(text),
                "html_len": len(text),
                "title": re.sub(r"\s+", " ", title.group(1)).strip()[:120] if title else "",
                "headers": {k: v for k, v in headers.items() if k.lower() in KEEP_HEADERS},
                "links": page_links,
                "resources": page_resources,
                "text": text[:MAX_TEXT_CHARS],
            })
            host = urlsplit(url).netloc
            assets.setdefault(host, {"host": host, "pages": 0, "status_codes": []})
            assets[host]["pages"] += 1
            assets[host]["status_codes"].append(status)
            if depth < scope.max_depth:
                queue.extend((link, depth + 1) for link in page_links)

        result = {
            "pages": pages,
            "assets": list(assets.values()),
            "stats": {"pages": len(pages), "requests": requests,
                      "seconds": round(time.time() - started, 2), "seed_urls": seeds},
            "blocked": blocked,
            "errors": errors,
        }
        print("[资产发现] 页面 %d 个 / 请求 %d 次 / 拦截 %d 次 / 错误 %d 条（%.1fs）"
              % (len(pages), requests, len(blocked), len(errors), time.time() - started))
        return {"result_key": json.dumps(result, ensure_ascii=False)}
    except Exception as exc:
        return _fail("资产发现执行异常：%s" % exc)
