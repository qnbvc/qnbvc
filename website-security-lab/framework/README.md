# 智能巡检智能体 · 骨架实现

纯标准库实现（无第三方依赖，可离线运行），用于把 [docs/02-智能体框架设计.md](../docs/02-智能体框架设计.md) 的架构落成可运行代码。

## 目录结构

```
framework/
├── config/authorization.example.json   # 授权、范围、周期、限速、敏感信息规则（与 docs/03 的 YAML 规范等价）
├── wn_agent/
│   ├── models.py        # 板块5：统一 Finding 数据模型 + 风险分级
│   ├── intake.py        # 子流程① 的两个代码节点：⑥ 输入与格式校验、⑨ 规则编译与冲突检测
│   ├── gate.py          # 板块1：授权闸门（范围校验 / 限速令牌 / 时间窗 / 档位管控 / 审计日志）
│   ├── fetcher.py       # 内容获取：LocalFetcher（离线演示）与 HttpFetcher（真实请求）
│   ├── tools.py         # 板块4：工具适配器协议 + 注册表 + 能力矩阵
│   ├── builtin_tools.py # 内置被动检测适配器（安全头 / 暴露面 / 敏感信息 / 篡改 / 挂马）
│   ├── agent.py         # 板块3：Planner → Router → Executor → Fuser → Verifier → Explainer
│   ├── memory.py        # 板块5：基线库 + 误报库 + 生命周期状态机
│   ├── report.py        # 板块6：报告导出（Markdown / JSON / CSV）
│   └── cli.py           # 命令行入口与离线演示
├── demo_site/           # 演示站点（第一轮：干净基线）
├── demo_site_after_tamper/  # 演示站点（第二轮：被注入隐藏 iframe / 恶意外链 / 混淆脚本）
├── tests/               # 30 条回归测试（巡检管线 12 条 + 配置校验 18 条）
└── out/                 # 演示输出（报告 + 审计日志），可删除后重新生成
```

## 快速开始

```powershell
cd framework
python -m wn_agent.cli --demo          # 离线两轮演示
python -m wn_agent.cli --validate-config config/authorization.example.json
python -m unittest discover -s tests   # 回归测试（30 条）
```

配置校验输出即子流程① 的 ⑥ / ⑨ 两个代码节点产物，可被「回显确认」交互节点直接消费：

```
结论：通过（错误 0 条，告警 2 条）
[WARN ] ERR-AUTH-005 authorization.document: 未找到授权书附件：evidence/auth-2026-0912.pdf
[WARN ] WARN-SCOPE-006 scope.domains[1]: *.example.gov.cn：通配子域会显著扩大扫描面…
规则编译结果：关键词 2 条、正则 3 条、文件类型 7 类、样例指纹 1 个、白名单 1 条
```

单次巡检（对本地站点快照）：

```powershell
python -m wn_agent.cli --site demo_site --url https://portal.example.gov.cn/ `
                       --config config/authorization.example.json `
                       --memory out/memory.json --out out --name my-report
```

对真实 HTTP 靶场巡检：

```powershell
python -m wn_agent.cli --http `
  --url http://127.0.0.1:8080/ `
  --config ..\range\authorization.range.json `
  --memory ..\range\out\memory.json --out ..\range\out --name range-pass
```

## 演示结果（实测输出）

| 轮次 | 页面 | 请求 | 原始命中 → 去重后 | 等级分布 |
| --- | --- | --- | --- | --- |
| 第一轮（建基线） | 4 | 48 | 25 → 17 | P0 8 / P1 2 / P2 6 / P3 1 |
| 第二轮（站点被篡改后复测） | 4 | 54 | 31 → 23 | P0 14 / P1 2 / P2 6 / P3 1 |

第二轮新增 6 条：**页面篡改 1 条**、**未授权外链 2 条**、**挂马特征 3 条**（混淆脚本、隐藏 iframe、隐藏元素暗链），
并给出"新增 / 复现 / 已消失"的基线对比。同时演示了授权闸门对范围外域名、未授权档位与排除路径的拦截。

> 说明：`demo_site_after_tamper/` 就是同一站点的"被篡改版本"，两轮共用同一个 memory 文件，用于演示基线对比与复测逻辑。

## 扩展一个新工具（三步）

```python
from wn_agent.models import Evidence, Finding, FindingType, Severity, Tier, now_iso
from wn_agent.tools import ToolMeta, ToolRegistry


class NucleiTool:
    meta = ToolMeta("nuclei", "vuln", Tier.T1,
                    "模板化漏洞与非破坏性 POC（排除侵入类模板）",
                    upstream="projectdiscovery/nuclei")

    def run(self, ctx):
        # 1) 所有请求必须经过 ctx.fetch → 自动过授权闸门与限速
        resp = ctx.fetch("https://target/path", Tier.T1, self.meta.name)
        # 2) 解析工具输出，统一收敛为 Finding
        return [Finding(asset=ctx.asset, url=ctx.page.url, ftype=FindingType.VULN,
                        rule_id="NUCLEI.CVE-2021-1234", title="组件已知漏洞",
                        severity=Severity.HIGH, tool=self.meta.name, tier=Tier.T1,
                        location="server", cwe="CWE-1104", confidence=0.75,
                        evidence=[Evidence("request_response", f"HTTP {resp.status}")],
                        first_seen=now_iso())]


registry = ToolRegistry()
registry.register(NucleiTool())
```

注册后 Router 会按"能力域 + 档位上限"自动把它纳入编排，无需改核心代码。

## 与评分指标的对应

| 指标 | 骨架中的体现 |
| --- | --- |
| 功能完整性 | 授权录入、页面发现、三类检测、告警与报告闭环（MD/JSON/CSV）、基线对比与复测 |
| 检测效果 | 去重键合并（25 → 17）、白名单降误报、二次确证（未复现项自动排除并计数） |
| 智能体能力 | 规划理由随报告输出、工具路由、执行留痕（blocked/error/no_tool）、证据/影响/修复建议 |
| 安全合规 | 闸门拦截范围外域名、未授权档位、排除路径；审计日志记录每一次放行与拦截 |
| 工程化 | 纯标准库、插件化工具注册、一键演示、12 条回归测试 |

## 已知局限（可继续演进）

1. 演示使用 `LocalFetcher`（本地目录快照），`HttpFetcher` 已在代码中就位但未做真实联网验证。
2. 真实工具（nuclei / gitleaks / YARA / Playwright 截图等）以适配器形式接入，骨架只内置了规则型被动检测的示例实现。
3. 存储用本地 JSON，生产需替换为 PostgreSQL + 对象存储（证据仓）。
4. 告警通道（邮件/Webhook）与看板未实现，配置项已在 `authorization.example.json` 中预留。
