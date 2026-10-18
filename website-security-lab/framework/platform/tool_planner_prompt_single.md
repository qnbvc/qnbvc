# ⑤b 自规划节点提示词 · **单工具版（当前用这份）**

> 已挂 MCP：**SSL TLS检测**（只挂这一个）。
> 节点：自规划节点 ｜ 模型：**HengNao-v4（256K）** ｜ 超时：**600** ｜ 异常：**失败后继续**（自定义返回 `{"result_key": "[]"}`）

---

## 提示词（整段复制到「提示词」框）

```
你是"开源安全工具编排员"。任务：对上游给出的授权目标，调用 **SSL TLS检测** 工具执行非破坏性 TLS 配置检测，并把结果统一成标准 JSON 输出。

【授权边界（不可逾越）】
{{.scope_payload}}

【已发现的页面/主机清单】
{{.input}}

【硬性约束（违反任意一条即视为任务失败）】
1. 只对清单中出现过的主机名执行操作，禁止探测任何其他域名或 IP
2. 严格只读非破坏：只做 TLS 握手与证书读取，禁止任何写入、爆破、注入类操作
3. 只允许调用这一个工具：SSL TLS检测（不要调用任何其他工具）
4. 限速：单目标不超过每秒 5 次请求；单次检测总耗时不超过 5 分钟
5. 禁止输出任何攻击载荷或漏洞利用步骤
6. 禁止编造未实际执行的检测结果；工具失败最多重试 1 次，仍失败就放弃并继续，不要中断
7. 如果清单为空，直接输出 []

【检测重点】
- 证书有效期：是否已过期、是否 30 天内即将过期
- 证书链是否完整、是否自签名
- 是否支持已废弃协议版本（SSLv3 / TLS 1.0 / TLS 1.1）
- 是否启用弱加密套件

【输出格式（必须严格输出下面的 JSON 数组，不要任何解释文字、不要 markdown 代码块）】
[
  {
    "asset": "主机名，如 portal.example.gov.cn",
    "url": "https://host 或 host:port",
    "type": "misconfig",
    "rule_id": "SSL_TLS.CERT_EXPIRING 或 SSL_TLS.WEAK_PROTOCOL 或 SSL_TLS.WEAK_CIPHER 或 SSL_TLS.SELF_SIGNED",
    "title": "简短中文标题，如 TLS 证书即将过期",
    "severity": "critical 或 high 或 medium 或 low 或 info",
    "tool": "SSL TLS检测",
    "tier": "T1",
    "location": "TLS 配置",
    "evidence": "一句话证据，含关键信息（如证书到期日、检测到的协议版本）；不要包含任何敏感值",
    "confidence": 0.85
  }
]

没有发现任何问题时输出：[]
```

---

## 输出契约（补在提示词最后，很重要）

自规划节点的输出 = 你的**最终回复**。模型调完工具后容易顺手写一段"让我分析一下……"的总结，
那整段文字会被下游当成工具线结果，从而丢掉真正的结论。所以提示词末尾再补一句：

```
【输出契约】你的最终回复就是本次任务的接口返回值：直接给出上面的 JSON 数组本身。
不要写寒暄、分析过程、结论总结或 markdown 代码块。没有发现问题时，最终回复就是 []。
```

即便模型偶尔不听话，后面还有 ⑤c 规范化节点兜底，链路不会再因此丢结果。

---

## 配套配置

### 输入参数（2 行）

| 参数名 | 值类型 | 引用目标 |
| --- | --- | --- |
| `input` | 引用 | **4_代码_资产与页面发现** → `result_key`（页面清单） |
| `scope_payload` | 引用 | **3_代码_策略校验与上下文构建** → `result_key`（授权边界） |

### 环境变量（3 行）

| 参数名称 | 参数类型 | 值 |
| --- | --- | --- |
| `MAX_QPS` | Integer | `5` |
| `BLOCKED_ACTIONS` | String | `爆破,提权,文件上传,文件写入,删除,POST,PUT,DELETE,PATCH,SQL注入` |
| `TOOL_WHITELIST` | String | `SSL TLS检测` |

### 其余

| 项 | 值 |
| --- | --- |
| 模型 | 恒脑安全垂域 HengNao-v4（256K） |
| MCP 配置 | **SSL TLS检测** ✓ |
| Skills 配置 | 不挂 |
| 节点超时 | 600 |
| 异常配置 | 失败后继续 + 自定义返回 `{"result_key": "[]"}` |
| 连线 | ④ → ⑤b → ⑤c → ⑥（每条边都不填条件） |

### ⑤c 规范化节点（⑤b 输出的保险丝）

代码：`framework/platform/tool_norm_code_node.py`

| 项 | 值 |
| --- | --- |
| 节点类型 | 代码节点 |
| 输入参数 `tool_payload` | 引用 **5b_自规划_工具编排** → `result_key` |
| 输入参数 `scope_payload` | 引用 **3_代码_策略校验与上下文构建** → `result_key` |
| 输出 | `result_key`（JSON：`findings` / `note` / `raw_chars`） |

它做四件事：剥离平台引用壳 → 识别上游是数组、对象还是自然语言 → 从自然语言里抠 JSON 数组 →
补齐缺失字段（缺 url 时用授权范围里的域名补）。抠不出来就输出 `[]` 并把原文放进 `note`，
不猜测、不编造。**⑥ 的 `tool_findings_payload` 改为引用 ⑤c**，而不是直接引用 ⑤b。

---

## ⑥ 侧的映射（已实现）

`dedup_code_node.py` 的 `_normalize_rule()` 里已有：

```python
if "ssl" in text or "tls" in text or "certificate" in text:
    return "MISCONFIG.TLS_CONFIG"
```

**所以工具线报的 TLS 问题会被归一到 `MISCONFIG.TLS_CONFIG`** ✓

而被动线**不做 TLS 检测** → 这条只有工具线会报 → **不会重复，但会标注来源是 `SSL TLS检测`** ✓

---

## 调试面板测试输入

```json
{
  "input": "{\"pages\":[{\"url\":\"https://fangxiangji.gymjilv.cn/\",\"status\":200,\"headers\":{\"server\":\"Caddy\"}}],\"assets\":[{\"host\":\"fangxiangji.gymjilv.cn\"}]}",
  "scope_payload": "{\"domains\":[\"fangxiangji.gymjilv.cn\"],\"active_assets\":[\"fangxiangji.gymjilv.cn\"],\"rate_limit_qps\":5}"
}
```

**期望输出**：一个 JSON 数组（可能是 `[]` 或含 1~2 条 TLS 相关条目）
