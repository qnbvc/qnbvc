# 网站安全智能巡检报告

| 项目 | 内容 |
| --- | --- |
| 巡检资产 | portal.example.gov.cn |
| 授权编号 | AUTH-2026-0912-001 |
| 完成时间 | 2026-10-11T19:43:33+08:00 |
| 发现页面 | 4 个 |
| 请求总数 | 48 次（含被拦截的拒绝记录） |
| 原始命中 → 去重后 | 25 → 17 条 |
| 二次验证后排除 | 0 条未复现项 |

## 一、风险概览

| 等级 | 数量 |
| --- | --- |
| P0 | 8 |
| P1 | 2 |
| P2 | 6 |
| P3 | 1 |

风险类型分布：vuln 2、leak 6、misconfig 9

## 二、风险明细

### 1. [P0] 敏感文件可公开访问：/backup.zip

- 风险类型：vuln　规则：`EXPOSURE.SENSITIVE_FILE.BACKUP_ZIP`
- 位置：https://portal.example.gov.cn/backup.zip　（/backup.zip）
- 发现工具：exposure-path　档位：T1
- 风险分：0.9504（置信度 0.98，状态 new，二次确证：是）
- 弱点分类：CWE-538　https://cwe.mitre.org/data/definitions/538.html
- 证据：
  - (request_response) GET https://portal.example.gov.cn/backup.zip -> HTTP 200，返回 50 字节
- 影响：备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。
- 修复建议：在 Web 服务器或网关屏蔽 /backup.zip 的公开访问并清理该类文件。

### 2. [P0] 敏感文件可公开访问：/config/database.yml

- 风险类型：vuln　规则：`EXPOSURE.SENSITIVE_FILE.CONFIG_DATABASE_YML`
- 位置：https://portal.example.gov.cn/config/database.yml　（/config/database.yml）
- 发现工具：exposure-path　档位：T1
- 风险分：0.9504（置信度 0.98，状态 new，二次确证：是）
- 弱点分类：CWE-538　https://cwe.mitre.org/data/definitions/538.html
- 证据：
  - (request_response) GET https://portal.example.gov.cn/config/database.yml -> HTTP 200，返回 123 字节
- 影响：备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。
- 修复建议：在 Web 服务器或网关屏蔽 /config/database.yml 的公开访问并清理该类文件。

### 3. [P0] 命中自定义敏感关键词：内部资料

- 风险类型：leak　规则：`LEAK.KEYWORD.内部资料`
- 位置：https://portal.example.gov.cn/news.html　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：内**料
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 4. [P0] 命中自定义敏感关键词：仅供内部使用

- 风险类型：leak　规则：`LEAK.KEYWORD.仅供内部使用`
- 位置：https://portal.example.gov.cn/news.html　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：仅****用
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 5. [P0] 命中敏感信息规则：中国大陆手机号

- 风险类型：leak　规则：`LEAK.REGEX.中国大陆手机号`
- 位置：https://portal.example.gov.cn/news.html　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：139*****222
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 6. [P0] 命中敏感信息规则：AccessKeyId

- 风险类型：leak　规则：`LEAK.REGEX.AccessKeyId`
- 位置：https://portal.example.gov.cn/news.html　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：acc******************************PLE
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 7. [P0] 命中敏感信息规则：中国大陆手机号

- 风险类型：leak　规则：`LEAK.REGEX.中国大陆手机号`
- 位置：https://portal.example.gov.cn/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：139*****222
  - (match_context) 命中值（已脱敏）：137*****333
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 8. [P0] 命中敏感信息规则：身份证号

- 风险类型：leak　规则：`LEAK.REGEX.身份证号`
- 位置：https://portal.example.gov.cn/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：110************23X
  - (match_context) 命中值（已脱敏）：310************321
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 9. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：https://portal.example.gov.cn/　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 10. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：https://portal.example.gov.cn/　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 11. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：https://portal.example.gov.cn/　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: ngi******8.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 12. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：https://portal.example.gov.cn/about.html　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: ngi******8.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 13. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：https://portal.example.gov.cn/news.html　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: ngi******8.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 14. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：https://portal.example.gov.cn/files/statistics.csv　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: ngi******8.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 15. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：https://portal.example.gov.cn/　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 16. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：https://portal.example.gov.cn/　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 17. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：https://portal.example.gov.cn/　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

## 三、智能体执行说明（可解释性）

规划的子任务与选择理由：

- [T0] misconfig（page）：站点存活且可获取响应，执行安全响应头与配置基线检查
- [T0] leak（page）：已配置敏感信息规则（关键词/正则/文件类型/样例），执行内容泄露检查
- [T0] malware（page）：执行外链白名单与挂马特征比对（含隐藏元素与混淆脚本）
- [T0] tamper（page）：首次巡检：仅建立内容基线，本周期不产出篡改结论
- [T1] vuln（asset）：资产 portal.example.gov.cn 已在授权白名单开启 T1 受控探测，执行备份文件与调试端点检查

工具执行留痕：共 20 次调用，其中被合规拦截 0 次、执行异常 0 次。

## 四、基线对比与生命周期

- 新增风险：17 条
- 仍然存在（复现）：0 条
- 本周期已消失（疑似修复）：0 条

## 五、合规审计摘要

- 出站请求：48 次（全部经授权闸门校验并记录）
- 被拒绝的请求：0 次

## 六、说明

- 本报告由智能巡检智能体生成；所有结论均可回溯到证据与来源工具。
- 默认仅执行被动档（T0）与受控探测档（T1）；主动验证档（T2）默认关闭。
- 证据中的敏感值已按策略脱敏，原始值单独加密存储。