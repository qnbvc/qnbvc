# 网站安全智能巡检报告

| 项目 | 内容 |
| --- | --- |
| 巡检资产 | 127.0.0.1:55774 |
| 授权编号 | AUTH-LAB-2026-001 |
| 完成时间 | 2026-10-18T23:19:31+08:00 |
| 发现页面 | 12 个 |
| 请求总数 | 143 次（含被拦截的拒绝记录） |
| 原始命中 → 去重后 | 109 → 71 条 |
| 二次验证后排除 | 0 条未复现项 |

## 一、风险概览

| 等级 | 数量 |
| --- | --- |
| P0 | 23 |
| P1 | 16 |
| P2 | 24 |
| P3 | 8 |

风险类型分布：vuln 3、leak 13、malware 5、tamper 2、misconfig 48

## 二、风险明细

### 1. [P0] 敏感文件可公开访问：/backup.zip

- 风险类型：vuln　规则：`EXPOSURE.SENSITIVE_FILE.BACKUP_ZIP`
- 位置：http://127.0.0.1:55774/backup.zip　（/backup.zip）
- 发现工具：exposure-path　档位：T1
- 风险分：0.9504（置信度 0.98，状态 new，二次确证：是）
- 弱点分类：CWE-538　https://cwe.mitre.org/data/definitions/538.html
- 证据：
  - (request_response) GET http://127.0.0.1:55774/backup.zip -> HTTP 200，返回 394 字节
- 影响：备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。
- 修复建议：在 Web 服务器或网关屏蔽 /backup.zip 的公开访问并清理该类文件。

### 2. [P0] 敏感文件可公开访问：/config/database.yml

- 风险类型：vuln　规则：`EXPOSURE.SENSITIVE_FILE.CONFIG_DATABASE_YML`
- 位置：http://127.0.0.1:55774/config/database.yml　（/config/database.yml）
- 发现工具：exposure-path　档位：T1
- 风险分：0.9504（置信度 0.98，状态 new，二次确证：是）
- 弱点分类：CWE-538　https://cwe.mitre.org/data/definitions/538.html
- 证据：
  - (request_response) GET http://127.0.0.1:55774/config/database.yml -> HTTP 200，返回 205 字节
- 影响：备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。
- 修复建议：在 Web 服务器或网关屏蔽 /config/database.yml 的公开访问并清理该类文件。

### 3. [P0] 敏感文件可公开访问：/.env

- 风险类型：vuln　规则：`EXPOSURE.SENSITIVE_FILE._ENV`
- 位置：http://127.0.0.1:55774/.env　（/.env）
- 发现工具：exposure-path　档位：T1
- 风险分：0.9504（置信度 0.98，状态 new，二次确证：是）
- 弱点分类：CWE-538　https://cwe.mitre.org/data/definitions/538.html
- 证据：
  - (request_response) GET http://127.0.0.1:55774/.env -> HTTP 200，返回 181 字节
- 影响：备份或配置文件可被匿名下载，可能导致凭据或业务数据整体泄露。
- 修复建议：在 Web 服务器或网关屏蔽 /.env 的公开访问并清理该类文件。

### 4. [P0] 命中样例样本指纹

- 风险类型：leak　规则：`LEAK.SAMPLE.MATCH`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.936（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：PRO********************026
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 5. [P0] 命中样例样本指纹

- 风险类型：leak　规则：`LEAK.SAMPLE.MATCH`
- 位置：http://127.0.0.1:55774/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.936（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：PRO********************026
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 6. [P0] 混淆脚本：eval + 解码链

- 风险类型：malware　规则：`MALWARE.EVAL_DECODE_CHAIN`
- 位置：http://127.0.0.1:55774/　（HTML 源码）
- 发现工具：malware-link　档位：T0
- 风险分：0.864（置信度 0.8，状态 new，二次确证：是）
- 弱点分类：CWE-506　https://cwe.mitre.org/data/definitions/506.html
- 证据：
  - (match_context) 命中片段：eval(unescape（规则 MALWARE.EVAL_DECODE_CHAIN）
- 影响：疑似挂马脚本或暗链，可能在用户浏览器执行恶意逻辑。
- 修复建议：隔离并人工审计该段脚本，确认后清理并排查写入路径。

### 7. [P0] 命中自定义敏感关键词：内部资料

- 风险类型：leak　规则：`LEAK.KEYWORD.内部资料`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：内**料
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 8. [P0] 命中自定义敏感关键词：PROJECT-INTERNAL-ONLY-2026

- 风险类型：leak　规则：`LEAK.KEYWORD.PROJECT-INTERNAL-ONLY-2026`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：PRO********************026
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 9. [P0] 命中敏感信息规则：中国大陆手机号

- 风险类型：leak　规则：`LEAK.REGEX.中国大陆手机号`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：139*****222
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 10. [P0] 命中敏感信息规则：AccessKeyId

- 风险类型：leak　规则：`LEAK.REGEX.AccessKeyId`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：acc******************************PLE
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 11. [P0] 命中敏感信息规则：疑似数据库口令

- 风险类型：leak　规则：`LEAK.REGEX.疑似数据库口令`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：pas******************************EAL
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 12. [P0] 命中自定义敏感关键词：内部资料

- 风险类型：leak　规则：`LEAK.KEYWORD.内部资料`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：内**料
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 13. [P0] 命中敏感信息规则：中国大陆手机号

- 风险类型：leak　规则：`LEAK.REGEX.中国大陆手机号`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：139*****222
  - (match_context) 命中值（已脱敏）：137*****333
  - (match_context) 命中值（已脱敏）：136*****444
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 14. [P0] 命中敏感信息规则：身份证号

- 风险类型：leak　规则：`LEAK.REGEX.身份证号`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：110************234
  - (match_context) 命中值（已脱敏）：110************345
  - (match_context) 命中值（已脱敏）：110************456
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 15. [P0] 命中自定义敏感关键词：内部资料

- 风险类型：leak　规则：`LEAK.KEYWORD.内部资料`
- 位置：http://127.0.0.1:55774/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：内**料
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 16. [P0] 命中自定义敏感关键词：PROJECT-INTERNAL-ONLY-2026

- 风险类型：leak　规则：`LEAK.KEYWORD.PROJECT-INTERNAL-ONLY-2026`
- 位置：http://127.0.0.1:55774/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：PRO********************026
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 17. [P0] 命中敏感信息规则：中国大陆手机号

- 风险类型：leak　规则：`LEAK.REGEX.中国大陆手机号`
- 位置：http://127.0.0.1:55774/files/statistics.csv　（页面内容）
- 发现工具：sensitive-scan　档位：T0
- 风险分：0.6552（置信度 0.95，状态 new，二次确证：是）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (match_context) 命中值（已脱敏）：139*****222
- 影响：敏感信息对公网可见，可能违反数据保护要求并造成信息泄露。
- 修复建议：下线或加密该内容、补充访问控制，并排查同类页面与模板。

### 18. [P0] 页面内容与基线不一致

- 风险类型：tamper　规则：`TAMPER.CONTENT_CHANGED`
- 位置：http://127.0.0.1:55774/　（正文）
- 发现工具：integrity-baseline　档位：T0
- 风险分：0.6384（置信度 0.9，状态 new，二次确证：是）
- 弱点分类：CWE-345　https://cwe.mitre.org/data/definitions/345.html
- 证据：
  - (diff) @@ -5,3 +5,3 @@
   <meta name="viewport" content="width=device-width, initial-scale=1">
-  <title>滨江市政务服务中心</title>
+  <title>系统升级中 · 滨江市政务服务中心</title>
   <link rel="stylesheet" href="/static/site.css">
@@ -20,13 +20,9 @@
- 影响：页面可能被非授权修改（挂马、暗链、内容篡改或误发布）。
- 修复建议：核对发布流水线确认变更来源；若非授权修改，立即回滚并排查入侵路径。

### 19. [P0] 页面内容与基线不一致

- 风险类型：tamper　规则：`TAMPER.CONTENT_CHANGED`
- 位置：http://127.0.0.1:55774/news.html　（正文）
- 发现工具：integrity-baseline　档位：T0
- 风险分：0.6384（置信度 0.9，状态 new，二次确证：是）
- 弱点分类：CWE-345　https://cwe.mitre.org/data/definitions/345.html
- 证据：
  - (diff) @@ -5,3 +5,3 @@
   <meta name="viewport" content="width=device-width, initial-scale=1">
-  <title>新闻动态 · 滨江市政务服务中心</title>
+  <title>紧急通知 · 滨江市政务服务中心</title>
   <link rel="stylesheet" href="/static/site.css">
@@ -18,11 +18,6 @@
- 影响：页面可能被非授权修改（挂马、暗链、内容篡改或误发布）。
- 修复建议：核对发布流水线确认变更来源；若非授权修改，立即回滚并排查入侵路径。

### 20. [P0] 页面引入未授权外部链接：cdn.badcdn.invalid

- 风险类型：malware　规则：`MALWARE.EXTERNAL_LINK`
- 位置：http://127.0.0.1:55774/　（cdn.badcdn.invalid）
- 发现工具：malware-link　档位：T0
- 风险分：0.6216（置信度 0.85，状态 new，二次确证：是）
- 弱点分类：CWE-829　https://cwe.mitre.org/data/definitions/829.html
- 证据：
  - (match_context) 外链：https://cdn.badcdn.invalid/pixel.gif
  - (match_context) 外链：https://cdn.badcdn.invalid/theme.js
- 影响：外部资源可被第三方替换，导致挂马、暗链或流量劫持。
- 修复建议：将外部资源本地化，或在 CSP 白名单中仅放行可信域名。

### 21. [P0] 页面引入未授权外部链接：cdn.badcdn.invalid

- 风险类型：malware　规则：`MALWARE.EXTERNAL_LINK`
- 位置：http://127.0.0.1:55774/news.html　（cdn.badcdn.invalid）
- 发现工具：malware-link　档位：T0
- 风险分：0.6216（置信度 0.85，状态 new，二次确证：是）
- 弱点分类：CWE-829　https://cwe.mitre.org/data/definitions/829.html
- 证据：
  - (match_context) 外链：https://cdn.badcdn.invalid/notice
- 影响：外部资源可被第三方替换，导致挂马、暗链或流量劫持。
- 修复建议：将外部资源本地化，或在 CSP 白名单中仅放行可信域名。

### 22. [P0] 隐藏 iframe（0 尺寸）

- 风险类型：malware　规则：`MALWARE.HIDDEN_IFRAME`
- 位置：http://127.0.0.1:55774/　（HTML 源码）
- 发现工具：malware-link　档位：T0
- 风险分：0.6048（置信度 0.8，状态 new，二次确证：是）
- 弱点分类：CWE-506　https://cwe.mitre.org/data/definitions/506.html
- 证据：
  - (match_context) 命中片段：<iframe src="https://cdn.badcdn.invalid/pixel.gif" width="0" height="0（规则 MALWARE.HIDDEN_IFRAME）
- 影响：疑似挂马脚本或暗链，可能在用户浏览器执行恶意逻辑。
- 修复建议：隔离并人工审计该段脚本，确认后清理并排查写入路径。

### 23. [P0] 隐藏元素（暗链特征）

- 风险类型：malware　规则：`MALWARE.HIDDEN_ELEMENT_LINK`
- 位置：http://127.0.0.1:55774/　（HTML 源码）
- 发现工具：malware-link　档位：T0
- 风险分：0.6048（置信度 0.8，状态 new，二次确证：是）
- 弱点分类：CWE-506　https://cwe.mitre.org/data/definitions/506.html
- 证据：
  - (match_context) 命中片段：style="display:none;font-size:0（规则 MALWARE.HIDDEN_ELEMENT_LINK）
- 影响：疑似挂马脚本或暗链，可能在用户浏览器执行恶意逻辑。
- 修复建议：隔离并人工审计该段脚本，确认后清理并排查写入路径。

### 24. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/leaks/　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 25. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/leaks/　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 26. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/weak/　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 27. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/weak/　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 28. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 29. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 30. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 31. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 32. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/weak/admin/　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 33. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/weak/admin/　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 34. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/weak/api/debug　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 35. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/weak/api/debug　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 36. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/weak/files/　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 37. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/weak/files/　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 38. [P1] CSP 缺失：content-security-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.content-security-policy`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（content-security-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 content-security-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 content-security-policy 响应头并回归验证。

### 39. [P1] HSTS 缺失：strict-transport-security

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.strict-transport-security`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（strict-transport-security）
- 发现工具：security-headers　档位：T0
- 风险分：0.3996（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-319　https://cwe.mitre.org/data/definitions/319.html
- 证据：
  - (request_response) 响应头中未出现 strict-transport-security
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 strict-transport-security 响应头并回归验证。

### 40. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/leaks/　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 41. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/weak/　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 42. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 43. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 44. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/weak/admin/　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 45. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/weak/api/debug　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 46. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/weak/files/　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 47. [P2] 响应头泄露服务器版本

- 风险类型：misconfig　规则：`MISCONFIG.SERVER_VERSION_LEAK`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（server）
- 发现工具：security-headers　档位：T0
- 风险分：0.1642（置信度 0.9，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) Server: Lab**********0.0
- 影响：攻击者可据此匹配已知漏洞版本。
- 修复建议：隐藏或泛化 Server 响应头中的版本信息。

### 48. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/leaks/　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 49. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/leaks/　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 50. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/weak/　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 51. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/weak/　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 52. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 53. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 54. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 55. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 56. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/weak/admin/　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 57. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/weak/admin/　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 58. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/weak/api/debug　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 59. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/weak/api/debug　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 60. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/weak/files/　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 61. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/weak/files/　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 62. [P2] 点击劫持防护头缺失：x-frame-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-frame-options`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（x-frame-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-1021　https://cwe.mitre.org/data/definitions/1021.html
- 证据：
  - (request_response) 响应头中未出现 x-frame-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-frame-options 响应头并回归验证。

### 63. [P2] MIME 嗅探防护头缺失：x-content-type-options

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.x-content-type-options`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（x-content-type-options）
- 发现工具：security-headers　档位：T0
- 风险分：0.1598（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-16　https://cwe.mitre.org/data/definitions/16.html
- 证据：
  - (request_response) 响应头中未出现 x-content-type-options
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 x-content-type-options 响应头并回归验证。

### 64. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/leaks/　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 65. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/weak/　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 66. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/leaks/internal-note.txt　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 67. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/leaks/staff.csv　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 68. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/weak/admin/　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 69. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/weak/api/debug　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 70. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/weak/files/　（referrer-policy）
- 发现工具：security-headers　档位：T0
- 风险分：0.0444（置信度 0.85，状态 new，二次确证：否）
- 弱点分类：CWE-200　https://cwe.mitre.org/data/definitions/200.html
- 证据：
  - (request_response) 响应头中未出现 referrer-policy
- 影响：浏览器端防护能力下降，可能被用于点击劫持、内容注入或降级攻击。
- 修复建议：在 Web 服务器或 CDN 为全站响应补充 referrer-policy 响应头并回归验证。

### 71. [P3] Referrer-Policy 缺失：referrer-policy

- 风险类型：misconfig　规则：`MISCONFIG.MISSING_HEADER.referrer-policy`
- 位置：http://127.0.0.1:55774/weak/files/debug.log　（referrer-policy）
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
- [T0] tamper（page）：存在历史基线，执行内容完整性 diff
- [T1] vuln（asset）：资产 127.0.0.1:55774 已在授权白名单开启 T1 受控探测，执行备份文件与调试端点检查

工具执行留痕：共 60 次调用，其中被合规拦截 0 次、执行异常 0 次。

## 四、基线对比与生命周期

- 新增风险：7 条
- 仍然存在（复现）：64 条
- 本周期已消失（疑似修复）：4 条

## 五、合规审计摘要

- 出站请求：143 次（全部经授权闸门校验并记录）
- 被拒绝的请求：0 次

## 六、说明

- 本报告由智能巡检智能体生成；所有结论均可回溯到证据与来源工具。
- 默认仅执行被动档（T0）与受控探测档（T1）；主动验证档（T2）默认关闭。
- 证据中的敏感值已按策略脱敏，原始值单独加密存储。