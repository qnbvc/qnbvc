"""恒巡 MCP 探针：列出服务端真实暴露的工具与参数 schema。

用途：接工具节点之前先确认"到底有哪些工具、参数名叫什么、有没有 target_url"，
避免在平台上照着文档猜配置、反复试错。

用法：
    python framework/platform/mcp_probe.py
    python framework/platform/mcp_probe.py --url http://118.178.130.95:8866/mcp --token <令牌>
    python framework/platform/mcp_probe.py --tool run_inspection      # 只看某个工具的入参

只做两件事：initialize + tools/list，不发任何扫描请求，对靶站零影响。
"""

import argparse
import json
import urllib.error
import urllib.request

DEFAULT_URL = "http://118.178.130.95:8866/mcp"


def _call(url, method, params=None, session="", token=""):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json, text/event-stream")
    if token:
        request.add_header("Authorization", "Bearer %s" % token)
    if session:
        request.add_header("Mcp-Session-Id", session)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8", "replace")
        return response.headers.get("Mcp-Session-Id", session), raw


def _parse_payload(raw):
    """MCP 可能返回纯 JSON，也可能是 SSE（data: {...}）。"""

    text = raw.strip()
    if text.startswith("{"):
        return json.loads(text)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            candidate = line[5:].strip()
            if candidate.startswith("{"):
                return json.loads(candidate)
    raise ValueError("无法解析响应：%s" % text[:200])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--token", default="")
    parser.add_argument("--tool", default="", help="只打印这个工具的入参 schema")
    args = parser.parse_args()

    try:
        session, _ = _call(args.url, "initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "codex-probe", "version": "1"}}, token=args.token)
        _, raw = _call(args.url, "tools/list", {}, session=session, token=args.token)
        payload = _parse_payload(raw)
    except urllib.error.HTTPError as exc:
        print("HTTP %s：%s" % (exc.code, exc.read().decode("utf-8", "replace")[:300]))
        print("→ 需要令牌时用 --token <令牌>（找队长要）")
        return
    except Exception as exc:
        print("连接失败：%s" % exc)
        print("→ 检查网络能不能访问 %s；也确认服务是否在运行" % args.url)
        return

    tools = (payload.get("result") or {}).get("tools") or []
    print("服务：%s" % args.url)
    print("工具数：%d" % len(tools))
    for tool in tools:
        name = tool.get("name", "")
        desc = (tool.get("description") or "").replace("\n", " ")[:70]
        print("  - %-24s %s" % (name, desc))
        if args.tool and name == args.tool:
            schema = tool.get("inputSchema") or {}
            print("\n【%s】入参 schema：" % name)
            print(json.dumps(schema, ensure_ascii=False, indent=2))
            print("\n【%s】完整说明：\n%s" % (name, tool.get("description") or ""))


if __name__ == "__main__":
    main()
