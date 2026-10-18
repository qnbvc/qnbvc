# 网站安全巡检靶场（本地运行 + 队友远程访问）

这套靶场是给「网站安全风险评估与敏感信息防泄露智能体」做联调和演示用的。它把比赛要求里的三类场景放进同一个受控站点：

- 漏洞与弱配置：缺失安全响应头、目录列表、调试接口、备份/配置/`.env` 暴露；
- 页面篡改与挂马：同一 URL 可在干净基线和篡改版本之间切换，包含隐藏 iframe、隐藏外链、`eval(unescape(...))`；
- 敏感信息泄露：自定义关键词、手机号、身份证号、AccessKey、数据库口令、CSV、日志和源码映射文件。

所有人员、密钥和业务数据都是合成的。靶场没有上传、登录爆破、命令执行或破坏性测试接口。

## 运行结构

```text
队友浏览器 ── Tailscale / Cloudflare Access ──┐
                                             ▼
                                    主机 TCP 8080
                                    LabGateway
                                      ├─ /          干净门户 / 篡改门户
                                      ├─ /weak/     弱配置、目录列表、调试接口
                                      └─ /leaks/    合成敏感文件
                                             ▲
巡检智能体 ── HTTP 只读请求 ─────────────────┘
控制端 ── POST /__lab/tamper|restore + X-Lab-Token
```

靶场只依赖 Python 3.10+ 标准库，不需要 Docker。Docker 只用于可选的 Juice Shop / WebGoat 扩展。

## 一分钟本地启动

Windows PowerShell：

```powershell
cd D:\Network_Security\website-security-lab
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\range\start.ps1
```

浏览器打开：

```text
http://127.0.0.1:8080/
```

如果 PowerShell 执行策略拦截脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\range\start.ps1
```

Linux / macOS：

```bash
cd /path/to/qnbvc/website-security-lab
LAB_CONTROL_TOKEN=team-lab-2026 ./range/start.sh
```

只想本机访问时绑定回环地址：

```powershell
.\range\start.ps1 -BindHost 127.0.0.1
```

不启动 Web 服务、直接跑完整「基线 → 篡改 → 复测」闭环：

```powershell
cd D:\Network_Security\website-security-lab
python range/demo.py
```

演示脚本会自动选择空闲端口、运行两轮巡检，并把第二轮报告写到 `range/out/demo/`。

## 靶场场景清单

| 场景 | 入口 | 预期结果 |
| --- | --- | --- |
| 正常门户基线 | `/`、`/news.html`、`/about.html` | 200，带 CSP、X-Frame-Options、HSTS 等安全头 |
| 敏感关键词 | `/news.html` | “内部资料”“仅供内部使用”命中 |
| 个人信息 | `/news.html`、`/files/statistics.csv`、`/leaks/staff.csv` | 合成手机号、身份证号命中 |
| 凭据泄露 | `/news.html`、`/leaks/internal-note.txt` | 合成 AccessKey、数据库口令命中 |
| 文件类型暴露 | `/files/statistics.csv`、`/weak/files/debug.log` | `.csv`、`.log` 等敏感类型命中 |
| 备份文件暴露 | `/backup.zip` | 返回一个真实可解压的合成 ZIP |
| 配置/环境文件暴露 | `/config/database.yml`、`/.env` | T1 受控探测命中 P0 |
| 弱配置 | `/weak/` | 故意不发送安全响应头，Server 泄露版本 |
| 目录列表 | `/weak/files/`、`/leaks/` | 故意开放目录浏览 |
| 调试接口 | `/weak/api/debug` | 返回合成配置和示例密钥 |
| 页面篡改 | 调用 `/__lab/tamper` 后访问 `/`、`/news.html` | 内容哈希变化，产生 TAMPER |
| 挂马/暗链 | 篡改后的 `/` | 隐藏 iframe、隐藏外链、混淆脚本特征 |
| 恢复基线 | 调用 `/__lab/restore` | 页面恢复干净版本 |
| 目录穿越防护 | `/%2e%2e/server.py` | 403，不会读出靶场源码 |

## 手动两轮演示

先在启动靶场的 PowerShell 窗口设置固定令牌，保证控制命令和服务器一致：

```powershell
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\range\start.ps1
```

另开一个 PowerShell 窗口，运行第一轮：

```powershell
cd D:\Network_Security\website-security-lab\framework
python -m wn_agent.cli --http `
  --url http://127.0.0.1:8080/ `
  --config ..\range\authorization.range.json `
  --memory ..\range\out\memory.json `
  --out ..\range\out `
  --name range-pass1
```

第一轮只建立基线，不应出现页面篡改结论。切换到篡改态：

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/__lab/tamper `
  -Headers @{ "X-Lab-Token" = "team-lab-2026" }
```

运行第二轮：

```powershell
python -m wn_agent.cli --http `
  --url http://127.0.0.1:8080/ `
  --config ..\range\authorization.range.json `
  --memory ..\range\out\memory.json `
  --out ..\range\out `
  --name range-pass2
```

此时应新增 `TAMPER` 和 `MALWARE`，并包含未授权外链 `cdn.badcdn.invalid`。恢复：

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/__lab/restore `
  -Headers @{ "X-Lab-Token" = "team-lab-2026" }
```

运行回归测试：

```powershell
cd D:\Network_Security\website-security-lab
python -B -m unittest discover -s range/tests -v
```

## 队友访问：优先用 Tailscale

这是最推荐的方式。它不要求路由器做端口映射，也不需要把 8080 暴露到公网。

1. 你和队友都安装 Tailscale，并登录同一个 tailnet。
2. 主机执行 `tailscale up`，再用 `tailscale ip -4` 查看地址，例如 `100.101.102.103`。
3. 主机用允许远程访问的方式启动：

```powershell
cd D:\Network_Security\website-security-lab
$env:LAB_CONTROL_TOKEN = "team-lab-2026"
.\range\start.ps1 -BindHost 0.0.0.0 -Port 8080
```

4. 队友打开：

```text
http://100.101.102.103:8080/
```

也可以用 MagicDNS 名称：

```text
http://<主机名>.<tailnet>.ts.net:8080/
```

如果希望使用 Tailscale 自动 HTTPS，可在主机上执行：

```powershell
tailscale serve --bg 8080
tailscale serve status
```

然后使用 `tailscale serve status` 显示的 HTTPS 地址。不同 Tailscale 版本参数可能略有差异，以本机 `tailscale serve --help` 为准。

如果队友能 ping 通 Tailscale IP 但打不开页面，再检查 Windows 防火墙是否放行 TCP 8080。只给可信网络临时放行，演示结束后删除规则：

```powershell
New-NetFirewallRule -DisplayName "Security Lab 8080" `
  -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Profile Private
```

## 同一局域网访问

适合队友和你在同一个 Wi-Fi 下：

1. 用 `ipconfig` 找到主机的局域网 IPv4，例如 `192.168.1.20`；
2. 主机用 `.\range\start.ps1 -BindHost 0.0.0.0` 启动；
3. 队友打开 `http://192.168.1.20:8080/`；
4. 打不开时检查 Windows 防火墙的 TCP 8080 入站规则。

不要在家庭路由器上把 8080 直接映射到公网。需要公网访问时用下面的受控隧道。

## 外网队友：Cloudflare Tunnel

临时演示可以使用 quick tunnel：

```powershell
cloudflared tunnel --url http://127.0.0.1:8080
```

它会输出一个公开 URL。由于这是公开入口，只放合成靶场，演示结束立即停止进程；需要切换页面时再在主机本地操作控制接口。

给评委或外部队友持续访问时，建议用命名隧道加 Cloudflare Access：

```powershell
cloudflared tunnel login
cloudflared tunnel create security-lab
cloudflared tunnel route dns security-lab lab.example.com
cloudflared tunnel run --url http://127.0.0.1:8080 security-lab
```

然后在 Cloudflare Zero Trust 中为该域名建立 Self-hosted Access 应用，策略限定邮箱或邮箱域。这样访问者先通过身份校验，再到达靶场。

公开展示时建议关闭控制接口：

```powershell
.\range\start.ps1 -NoControl
```

关闭后 `/__lab/tamper` 和 `/__lab/restore` 返回 404，页面仍可正常浏览。

## 远程巡检时的授权配置

靶场默认配置只给本机 `127.0.0.1:8080` 和 `localhost:8080` 开启 T1 主动探测。队友如果从自己的电脑运行智能体，需要把实际目标加入 `range/authorization.range.json`：

```json
{
  "scope": {
    "domains": ["127.0.0.1", "localhost", "lab.example.com"],
    "ip_ranges": ["127.0.0.0/8", "100.64.0.0/10"]
  },
  "safety": {
    "active_assets": ["127.0.0.1:8080", "lab.example.com"]
  }
}
```

如果通过 Tailscale IP 访问，把对应 `100.x.x.x:8080` 加入 `active_assets`。T0 被动检查可以只靠 `100.64.0.0/10` 放行，T1 探测必须精确授权资产。

这只是靶场配置。接入真实单位资产时，应改成真实授权编号、授权书、有效期和最小范围，不要沿用通配范围。

## 可选的已知漏洞应用

内置场景已经覆盖弱配置、暴露面、篡改、挂马和敏感信息。需要联调 nuclei / ZAP 的真实 CVE 模板时，可以额外启动上游维护的漏洞应用：

```powershell
docker compose -f range/compose.yml --profile vulnerable up -d
```

- OWASP Juice Shop：`http://127.0.0.1:3000/`
- OWASP WebGoat：`http://127.0.0.1:8081/WebGoat/`

容器端口只绑定回环地址。队友需要访问时，用 Tailscale 单独转发对应端口，不要直接把脆弱应用暴露到公网。

## 安全边界

- 不存放真实账号、密钥、人员信息或单位业务数据；
- 不提供文件上传、口令爆破、注入数据导出、命令执行或拒绝服务接口；
- 篡改页面只返回静态合成内容，CSP 仍会限制实际浏览器执行外部资源；
- 控制接口使用 `X-Lab-Token`，错误令牌返回 403；
- 路径解析限制在靶场根目录，目录穿越返回 403；
- 对外演示优先使用 Tailscale 或 Cloudflare Access，并尽量加 `-NoControl`。

## 交付时可直接使用的证据

- 架构与技术选型：本文件「运行结构」和 `docs/02-智能体框架设计.md`；
- 场景覆盖矩阵：本文件「靶场场景清单」；
- 自动化验证：`range/tests/test_range.py`，包含端口、响应头、ZIP、令牌、目录穿越和双轮巡检；
- 演示报告：`range/out/demo/range-pass2.md`；
- 工具与合规基线：`docs/03-开源工具清单与合规基线.md`。
