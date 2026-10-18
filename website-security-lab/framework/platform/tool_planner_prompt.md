# ⑤b 自规划节点 · 工具编排提示词

> 用途：并行于 ⑤ 代码_三类检测，调用 MCP 开源安全工具做主动检测，输出统一 Finding JSON 供 ⑥ 归并。
> 节点类型：**自规划节点** ｜ 模型：**HengNao-v4（256K）** ｜ 超时：**600** ｜ 异常：**失败后继续**

---

## 提示词（整段复制到「提示词」框）

```
你是"开源安全工具编排员"。上游会给你【授权边界】和【已发现的页面/主机清单】，你要用 MCP 安全工具对清单内的目标执行非破坏性检测，并把结果统一成标准 JSON 输出。

【授权边界（不可逾越）】
{{.scope_payload}}

【已发现的页面/主机清单】
{{.input}}

【硬性约束（违反任意一条即视为任务失败）】
1. 只对清单中出现过的主机名执行操作，禁止探测任何其他域名或 IP
2. 严格只读非破坏：禁止 SQL 注入、口令爆破、文件上传、数据写入、提权、拒绝服务类操作
3. 只允许使用这些工具：nuclei（排除 intr / fuzz / dos 类模板）、SSL/TLS 配置检测、子域名发现
4. 限速：单目标不超过每秒 5 次请求；单次检测总耗时不超过 5 分钟
5. 禁止输出任何攻击载荷、exp 代码或漏洞利用步骤
6. 禁止编造未实际执行的工具结果；工具失败最多重试 1 次，仍失败就放弃该工具并继续，不要中断
7. 如果清单为空，直接输出 []

【执行步骤】
1. 从清单里提取去重后的主机与 URL 列表
2. 对每个目标依次执行：SSL/TLS 配置检测 → 模板化漏洞扫描（仅非入侵类模板）
3. 每条命中记录：工具名、命中的模板/规则 ID、目标 URL、关键证据片段

【输出格式（必须严格输出下面的 JSON 数组，不要任何解释文字、不要 markdown 代码块）】
[
  {
    "asset": "主机名，如 portal.example.gov.cn",
    "url": "具体 URL 或 host:port",
    "type": "vuln 或 misconfig 或 leak 或 malware 或 tamper",
    "rule_id": "工具名.规则ID，如 NUCLEI.http-missing-security-headers",
    "title": "简短中文标题，如 缺少安全响应头",
    "severity": "critical 或 high 或 medium 或 low 或 info",
    "tool": "nuclei 或 sslscan 或 subfinder",
    "tier": "T1",
    "location": "命中的具体位置，如 响应头 / TLS 配置",
    "evidence": "一句话证据，含关键响应片段；不要包含任何敏感值",
    "confidence": 0.8
  }
]

没有发现任何问题时输出：[]
```

---

## 节点配置速查

| 配置项 | 值 |
| --- | --- |
| 节点名称 | `⑤b 自规划_工具编排` |
| 输入参数 1 | `input` → 引用 **④ 代码_资产与页面发现 - result_key**（页面清单） |
| 输入参数 2 | `scope_payload` → 引用 **③ 代码_策略校验与上下文构建 - result_key**（授权边界） |
| 环境变量 | `MAX_QPS=5`、`BLOCKED_ACTIONS=爆破,提权,文件上传,文件写入,删除,POST,PUT,DELETE,PATCH`、`TOOL_WHITELIST=nuclei,sslscan,subfinder` |
| 模型 | 恒脑安全垂域 **HengNao-v4**（256K） |
| MCP 配置 | **先只挂 1 个**（推荐「SSL_TLS检测」或「Nuclei漏洞扫描」），跑通后再加 |
| Skills 配置 | 不挂 |
| 节点超时 | **600**（工具扫描慢） |
| 异常配置 | **失败后继续** ← 关键：工具线挂了不能拖垮主线 |
| 连线 | ④ → ⑤b → ⑥ |

---

## 画布排布

```
        ③ 代码_策略校验与上下文构建
              │ gate_payload
              ▼
        ④ 代码_资产与页面发现
              │ pages_payload
      ┌───────┴────────┐
      ▼                ▼
⑤ 代码_三类检测    ⑤b 自规划_工具编排
  （被动·秒级）      （主动·MCP 工具·分钟级）
  raw_findings       tool_findings
      └───────┬────────┘
              ▼
     ⑥ 代码_去重验证分级
              ▼
           ⑧ → ⑨ → ⑩
```

---

## ⑥ 的配套改动（已在 dedup_code_node.py 中实现）

| 改动 | 内容 |
| --- | --- |
| 新增输入参数 | `tool_findings_payload` → 引用 **⑤b 自规划_工具编排 - result_key** |
| 容错解析 | `_parse_tool_findings()`：剥壳、剥代码块、抠 JSON 数组 |
| 字段补齐 | 缺 `tool`/`tier`/`severity`/`confidence`/`location` 时给默认值 |
| **跨来源归一化** | `_normalize_rule()`：把 nuclei 的 `http-missing-security-headers` 等映射到与被动线一致的规则 ID，使两条线报的同一问题能合并 |

**合并效果**（本地实测）：

```
原始命中 2 → 去重后 1（压缩 50%）
[P1] CSP 缺失：content-security-policy
     来源=['headers-baseline', 'nuclei']   置信度 0.80 → 0.95   confirmed
```

---

## 分阶段实施建议

| 阶段 | 动作 | 验收标准 |
| --- | --- | --- |
| 1 | 建 ⑤b，**只挂 1 个 MCP**，用调试面板单独跑 | 输出是合法 Finding JSON 数组 |
| 2 | 喂一个**范围外的域名**测试 | 它拒绝执行（合规约束生效） |
| 3 | 加第 2 个 MCP 工具 | 两个工具的结果都在输出里 |
| 4 | 接进主流程（④ 分两路），⑥ 加输入参数 + 换代码 | 两条线都产出，⑥ 合并成功 |
| 5 | 跑端到端 + 记录测试用例 | 报告里能看到双来源互证 |

**不要一次挂 14 个工具**——v1 就是这么失败的，错在哪都看不出来。
